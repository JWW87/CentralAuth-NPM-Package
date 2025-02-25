var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { EncryptJWT, jwtDecrypt } from "jose";
//Private method for parsing a cookie string in a request header
const parseCookie = (cookieString) => ((cookieString === null || cookieString === void 0 ? void 0 : cookieString.split(';').map(v => v.split('=')).reduce((acc, v) => {
    acc[decodeURIComponent(v[0].trim())] = decodeURIComponent(v[1].trim());
    return acc;
}, {})) || {});
//Extension of the Error object to throw a validation error
export class ValidationError extends Error {
    constructor(error) {
        super(error.message);
        this.errorCode = error.errorCode;
    }
}
//Class for CentralAuth
export class CentralAuthClass {
    //Constructor method to set all instance variable
    constructor({ clientId, secret, authBaseUrl, callbackUrl, cache, debug }) {
        //Private method to check whether all variable are set for a specific action
        //Will throw a ValidationError when a check fails
        this.checkData = (action) => {
            let error = null;
            if (typeof this.clientId === "undefined")
                error = { errorCode: "organizationIdMissing", message: "The organization ID is missing. This ID can be found on the organization page in your admin console." };
            if (!this.secret)
                error = { errorCode: "secretMissing", message: "The secret is missing. The secret is shown only once at the creation of an organization and should never be exposed publicly or stored unsafely." };
            if (!this.callbackUrl)
                error = { errorCode: "callbackUrlMissing", message: "The callback URL is missing." };
            if (!this.authBaseUrl)
                error = { errorCode: "authBaseUrlMissing", message: "The base URL for the organization is missing. The base URL is either the internal base URL or a custom domain for your organization." };
            if ((action == "callback" || action == "verify") && !this.token)
                error = { errorCode: "tokenMissing", message: "The JSON Web Token is missing. A JWT must be created in the callback after a successful login attempt." };
            if (action == "me" && !this.token)
                error = { errorCode: "tokenMissing", message: "The JSON Web Token is missing. This means the user is not logged in or the token is invalid." };
            if (error) {
                if (this.debug)
                    console.error(`[CENTRALAUTH DEBUG] Data check failed for client ${this.clientId || "CentralAuth"} in ${action}: ${error.message}`);
                throw new ValidationError(error);
            }
        };
        //Private method to get the decoded token, either from the cookie of the token bearer in the headers
        this.getDecodedToken = (headers) => __awaiter(this, void 0, void 0, function* () {
            //Populate the token from token bearer or cookie
            const authHeader = headers.get("Authorization");
            if (authHeader)
                yield this.setTokenFromTokenBearer(headers);
            else
                yield this.setTokenFromCookie(headers);
            this.checkData("callback");
            try {
                //Decode the JWT
                const textEncoder = new TextEncoder();
                const { payload: decodedToken } = yield jwtDecrypt(this.token, textEncoder.encode(this.secret));
                return decodedToken;
            }
            catch (error) {
                if (this.debug)
                    console.error(`[CENTRALAUTH DEBUG] Failed to decode token for client ${this.clientId || "CentralAuth"}: ${error.message}`);
                throw new ValidationError({ errorCode: error === null || error === void 0 ? void 0 : error.name, message: error === null || error === void 0 ? void 0 : error.message });
            }
        });
        //Private method to set the payload of the JWT
        this.setToken = (payload) => __awaiter(this, void 0, void 0, function* () {
            const textEncoder = new TextEncoder();
            this.token = yield new EncryptJWT(payload)
                .setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512" })
                .setIssuedAt()
                .encrypt(textEncoder.encode(this.secret));
        });
        //Private method to get the returnTo URL from the config object or current request
        this.getReturnToURL = (req, config) => {
            const url = new URL(req.url);
            const returnToParam = url.searchParams.get("returnTo");
            const headers = req.headers;
            let returnTo = "";
            //Set returnTo when explicitly given in the config object
            if (config === null || config === void 0 ? void 0 : config.returnTo)
                returnTo = config.returnTo;
            else if (returnToParam)
                returnTo = returnToParam; //Set returnTo to any returnTo query param in the URL
            else {
                const referrer = headers.get("referer");
                //Set returnTo to the referrer in the request when present
                if (referrer && !referrer.startsWith("about"))
                    returnTo = referrer;
                else {
                    //Otherwise fallback to the origin
                    returnTo = new URL(req.url).origin;
                }
            }
            return returnTo;
        };
        //Private method to return the client user agent from request headers
        this.getUserAgent = (headers) => {
            const userAgent = headers.get("user-agent");
            return userAgent || "native";
        };
        //Private method to return the client IP address from request headers
        this.getIPAddress = (headers) => {
            const realIp = headers.get("x-real-ip");
            const forwardedFor = headers.get("x-forwarded-for");
            const ip = forwardedFor || realIp || null;
            //The IP address might consist of multiple IP addresses, seperated by commas. Only return the first IP address
            return ip ? ip.split(",")[0] : "0.0.0.0";
        };
        //Private method to get the user data from cache or the CentralAuth server
        //Will throw an error when the request fails
        //Will update the contents of the token with user and session data
        this.getUser = (jwtPayload, userAgent, ipAddress) => __awaiter(this, void 0, void 0, function* () {
            var _a, _b;
            if (this.user)
                return this.user;
            else {
                this.checkData("me");
                const { user, session } = jwtPayload;
                //Check if user data should be fetched from cache
                const cached = user && session && !!(session === null || session === void 0 ? void 0 : session.lastSync) && ((_a = this.cache) === null || _a === void 0 ? void 0 : _a.enabled) && this.cache.cacheLifeTime ? new Date().getTime() - new Date(session.lastSync).getTime() < this.cache.cacheLifeTime * 1000 : false;
                if (user && session && cached) {
                    if (this.debug)
                        console.log(`[CENTRALAUTH DEBUG] User data fetched from cache for client ${this.clientId || "CentralAuth"}.`);
                    //Check if hijack protection is disabled or the IP address and user agent of the current user matches the IP address and user agent of the session
                    if (((_b = this.cache) === null || _b === void 0 ? void 0 : _b.cacheHijackProtection) === false || (session.ipAddress === ipAddress && session.userAgent === userAgent))
                        this.user = user;
                    else {
                        if (this.debug)
                            console.error(`[CENTRALAUTH DEBUG] Cached data could not be fetched for client ${this.clientId || "CentralAuth"}.`);
                        this.user = undefined;
                        throw new ValidationError({ errorCode: "sessionInvalid", message: "The session is invalid. The IP address and/or user agent of the current request do not match the IP address and/or user agent of the session." });
                    }
                }
                else {
                    //Get the user and session data from the CentralAuth server
                    const headers = new Headers();
                    headers.set("Authorization", `Bearer ${this.token}`);
                    //Set the user agent to the user agent of the current request
                    headers.set("user-agent", userAgent);
                    //Set the custom auth-ip header with the IP address of the current request
                    headers.set("auth-ip", ipAddress);
                    //Construct the URL
                    const requestUrl = new URL(`${this.authBaseUrl}/api/v1/me/${jwtPayload.sessionId}`);
                    const callbackUrl = new URL(this.callbackUrl);
                    requestUrl.searchParams.set("domain", callbackUrl.origin);
                    const response = yield fetch(requestUrl.toString(), { headers });
                    if (!response.ok) {
                        const error = yield response.json();
                        if (this.debug)
                            console.error(`[CENTRALAUTH DEBUG] Failed to fetch user data from the server for client ${this.clientId || "CentralAuth"}: ${error.message}`);
                        throw new ValidationError(error);
                    }
                    this.user = (yield response.json());
                    if (this.user && session) {
                        //Update the payload in the session token cookie
                        yield this.setToken(Object.assign(Object.assign({}, jwtPayload), { user: this.user, session: Object.assign(Object.assign({}, session), { lastSync: cached ? session.lastSync : new Date().toISOString() }) }));
                    }
                }
            }
        });
        //Private method to populate the token argument from the cookie in the session
        this.setTokenFromCookie = (headers) => __awaiter(this, void 0, void 0, function* () {
            const cookies = parseCookie(headers.get("cookie"));
            //Check for a sessionToken in the cookies
            if (cookies["sessionToken"])
                this.token = cookies["sessionToken"];
        });
        //Private method to populate the token argument from the JWT in the token bearer header
        this.setTokenFromTokenBearer = (headers) => __awaiter(this, void 0, void 0, function* () {
            const authHeader = headers.get("Authorization");
            //Check for a token bearer header
            if (authHeader && authHeader.startsWith("Bearer "))
                this.token = authHeader.substring(7);
        });
        //Public method to get the user data from the current request headers
        //The JWT will be set based on the sessionToken cookie or token bearer in the request header
        //Will throw an error when the request fails or the token could not be decoded
        this.getUserData = (headers) => __awaiter(this, void 0, void 0, function* () {
            //Decode the token
            const jwtPayload = yield this.getDecodedToken(headers);
            //Get the user data from cache or CentralAuth
            yield this.getUser(jwtPayload, this.getUserAgent(headers), this.getIPAddress(headers));
            return this.user || null;
        });
        //Public method to start the login procedure
        //Will throw an error when the procedure could not be started
        this.login = (req, config) => __awaiter(this, void 0, void 0, function* () {
            this.checkData("login");
            const returnTo = this.getReturnToURL(req, config);
            const callbackUrl = new URL(this.callbackUrl);
            if (returnTo)
                callbackUrl.searchParams.set("returnTo", returnTo);
            //Check for custom translations in the config
            const textEncoder = new TextEncoder();
            const translations = (config === null || config === void 0 ? void 0 : config.translations) ? textEncoder.encode(JSON.stringify(config.translations)) : null;
            //Redirect to the login page
            const loginUrl = new URL(`${this.authBaseUrl}/login/${this.clientId || ""}`);
            //Add an error message when given
            if (config === null || config === void 0 ? void 0 : config.errorMessage)
                loginUrl.searchParams.set("errorMessage", config === null || config === void 0 ? void 0 : config.errorMessage);
            //Add a default email address when given
            if (config === null || config === void 0 ? void 0 : config.emailAddress)
                loginUrl.searchParams.set("emailAddress", config === null || config === void 0 ? void 0 : config.emailAddress);
            //Add translations when given
            if (translations)
                loginUrl.searchParams.set("translations", Buffer.from(translations).toString("base64"));
            //Add embed boolean when given
            if (config === null || config === void 0 ? void 0 : config.embed)
                loginUrl.searchParams.set("embed", "1");
            loginUrl.searchParams.set("callbackUrl", callbackUrl.toString());
            if (this.debug)
                console.log(`[CENTRALAUTH DEBUG] Starting login procedure for client ${this.clientId || "CentralAuth"}, redirecting to ${loginUrl.toString()}.`);
            return Response.redirect(loginUrl.toString());
        });
        //Public method for the callback procedure when returning from CentralAuth
        this.callback = (req, config) => __awaiter(this, void 0, void 0, function* () {
            const res = yield this.processCallback(req);
            //When an onAfterCallback function is given, call it with the user data
            //The onAfterCallback function may return a new/altered response, which will be returned instead of the default response object
            let callbackResponse = null;
            if (config === null || config === void 0 ? void 0 : config.onAfterCallback)
                callbackResponse = yield config.onAfterCallback(req, res, this.user);
            //Set a cookie with the JWT and redirect to the returnTo URL
            return callbackResponse || res;
        });
        //Protected method for processing the callback
        //This method will automatically verify the JWT payload and set the sessionToken cookie
        //Optionally calls a custom callback function when given with the user data as an argument
        //Returns a Response with a redirection to the returnTo URL
        //Will throw an error when the verification procedure fails or the user data could not be fetched
        this.processCallback = (req) => __awaiter(this, void 0, void 0, function* () {
            const url = new URL(req.url);
            const searchParams = url.searchParams;
            const returnTo = searchParams.get("returnTo") || url.origin;
            const sessionId = searchParams.get("sessionId");
            const verificationState = searchParams.get("verificationState");
            const errorCode = searchParams.get("errorCode");
            const errorMessage = searchParams.get("errorMessage");
            if (errorCode) {
                //When the error code is set, something went wrong in the login procedure
                //Throw a ValidationError
                if (this.debug)
                    console.error(`[CENTRALAUTH DEBUG] Error in login procedure for client ${this.clientId || "CentralAuth"}: ${errorMessage}`);
                throw new ValidationError({ errorCode: errorCode, message: errorMessage || "" });
            }
            if (!sessionId || !verificationState) {
                if (this.debug)
                    console.error(`[CENTRALAUTH DEBUG] Callback could not be processed for client ${this.clientId || "CentralAuth"}, missing session ID and/or verification state.`);
                throw new ValidationError({ errorCode: "missingFields", message: "The session ID and/or verification state are missing in the callback URL." });
            }
            //Build the JWT with the session ID and verification state as payload
            yield this.setToken({ sessionId, verificationState });
            this.checkData("callback");
            //Make a request to the verification endpoint to verify this session at CentralAuth
            const headers = new Headers();
            headers.set("Authorization", `Bearer ${this.token}`);
            //Construct the URL
            const requestUrl = new URL(`${this.authBaseUrl}/api/v1/verify/${sessionId}/${verificationState}`);
            const callbackUrl = new URL(this.callbackUrl);
            requestUrl.searchParams.set("domain", callbackUrl.origin);
            const verifyResponse = yield fetch(requestUrl, { headers });
            if (!verifyResponse.ok) {
                const error = yield verifyResponse.json();
                if (this.debug)
                    console.error(`[CENTRALAUTH DEBUG] Failed to verify session for client ${this.clientId || "CentralAuth"}: ${error.message}`);
                throw new ValidationError(error);
            }
            const response = yield verifyResponse.json();
            this.user = response.user;
            //Add the user and session data to the token
            yield this.setToken(Object.assign({ sessionId,
                verificationState }, response));
            //Set the default response object
            let res = new Response(null, {
                status: 302,
                headers: {
                    "Location": returnTo,
                    "Set-Cookie": `sessionToken=${this.token}; Path=/; HttpOnly; Max-Age=100000000; SameSite=Lax; Secure`
                }
            });
            //Set a cookie with the JWT and redirect to the returnTo URL
            return res;
        });
        //Public method to get the user data from the current request
        //This method wraps getUserData and returns a Response with the user data as JSON in the body
        //Will return a NULL response on error
        this.me = (req) => __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = req.headers;
                yield this.getUserData(headers);
                //Return the user and update the session token cookie
                return Response.json(this.user, {
                    headers: {
                        "Set-Cookie": `sessionToken=${this.token}; Path=/; HttpOnly; Max-Age=100000000; SameSite=Lax; Secure`
                    }
                });
            }
            catch (error) {
                //When an error occurs, assume the user session is not valid anymore
                //Delete the cookie
                if (this.debug)
                    console.error(`[CENTRALAUTH DEBUG] Error fetching user data from cache or CentralAuth server or validation error for client ${this.clientId || "CentralAuth"}: ${error === null || error === void 0 ? void 0 : error.message}`);
                return Response.json(null, {
                    headers: {
                        "Set-Cookie": "sessionToken= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure"
                    }
                });
            }
        });
        //Public method to logout
        this.logout = (req, config) => __awaiter(this, void 0, void 0, function* () {
            const returnTo = this.getReturnToURL(req, config);
            const headerList = req.headers;
            try {
                if (config === null || config === void 0 ? void 0 : config.LogoutSessionWide) {
                    //To log out session wide, invalidate the session at CentralAuth
                    //Get the session ID from the token
                    const { sessionId } = yield this.getDecodedToken(headerList);
                    //Make a request to the log out endpoint to invalidate this session at CentralAuth
                    const headers = new Headers();
                    headers.set("Authorization", `Bearer ${this.token}`);
                    const logoutResponse = yield fetch(`${this.authBaseUrl}/api/v1/logout/${sessionId}`, { headers });
                    if (!logoutResponse.ok) {
                        const error = yield logoutResponse.json();
                        throw new ValidationError(error);
                    }
                }
            }
            catch (error) {
                if (this.debug)
                    console.error(`[CENTRALAUTH DEBUG] Error logging out session-wide for client ${this.clientId || "CentralAuth"}: ${error === null || error === void 0 ? void 0 : error.message}`);
            }
            finally {
                //Unset the cookie and redirect to the returnTo URL
                return new Response(null, {
                    status: 302,
                    headers: {
                        "Location": returnTo,
                        "Set-Cookie": "sessionToken= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure"
                    }
                });
            }
        });
        if (debug)
            console.log(`[CENTRALAUTH DEBUG] CentralAuth class instantiated for client ${clientId || "CentralAuth"}.`);
        this.clientId = clientId;
        this.secret = secret;
        this.authBaseUrl = authBaseUrl;
        this.callbackUrl = callbackUrl;
        this.cache = cache;
        this.debug = debug;
    }
}
//Define a subclass for HTTP based servers
export class CentralAuthHTTPClass extends CentralAuthClass {
    constructor() {
        super(...arguments);
        //Private method for converting a HTTP Request to a Fetch API Request
        this.httpRequestToFetchRequest = (httpRequest) => {
            const baseUrl = new URL(this.callbackUrl);
            const fetchRequest = new Request(new URL(httpRequest.url, baseUrl.origin), {
                headers: new Headers(Object.assign({}, httpRequest.headers))
            });
            return fetchRequest;
        };
        //Private method for converting a Fetch API response to an HTTP Response
        this.fetchResponseToHttpResponse = (fetchResponse, httpResponse) => __awaiter(this, void 0, void 0, function* () {
            const entries = fetchResponse.headers.entries();
            const httpHeaders = {};
            for (const entry of entries)
                httpHeaders[entry[0]] = entry[1];
            const body = yield fetchResponse.text();
            httpResponse.writeHead(fetchResponse.status, httpHeaders).end(body);
        });
        //Overloaded method for getUserData
        this.getUserDataHTTP = (req) => __awaiter(this, void 0, void 0, function* () {
            const request = this.httpRequestToFetchRequest(req);
            return yield this.getUserData(request.headers);
        });
        //Overloaded method for login
        this.loginHTTP = (req, res, config) => __awaiter(this, void 0, void 0, function* () {
            const fetchResponse = yield this.login(this.httpRequestToFetchRequest(req), config);
            yield this.fetchResponseToHttpResponse(fetchResponse, res);
        });
        //Overloaded method for callback
        this.callbackHTTP = (req, res, config) => __awaiter(this, void 0, void 0, function* () {
            const fetchResponse = yield this.processCallback(this.httpRequestToFetchRequest(req));
            //When an onAfterCallback function is given, call it with the user data
            //The onAfterCallback function may return a new/altered response, which will be returned instead of the default response object
            let callbackResponse = null;
            if (config === null || config === void 0 ? void 0 : config.onAfterCallback)
                callbackResponse = yield config.onAfterCallback(req, res, fetchResponse, this.user);
            yield this.fetchResponseToHttpResponse(callbackResponse || fetchResponse, res);
        });
        //Overloaded method for logout
        this.logoutHTTP = (req, res, config) => __awaiter(this, void 0, void 0, function* () {
            const fetchResponse = yield this.logout(this.httpRequestToFetchRequest(req), config);
            yield this.fetchResponseToHttpResponse(fetchResponse, res);
        });
        //Overloaded method for me
        this.meHTTP = (req, res) => __awaiter(this, void 0, void 0, function* () {
            const fetchResponse = yield this.me(this.httpRequestToFetchRequest(req));
            yield this.fetchResponseToHttpResponse(fetchResponse, res);
        });
    }
}
//# sourceMappingURL=server.js.map