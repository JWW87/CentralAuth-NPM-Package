var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { jwtDecrypt } from "jose";
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
    constructor({ clientId, secret, authBaseUrl, callbackUrl, debug, unsafeIncludeUser }) {
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
            if (action == "user" && !this.token)
                error = { errorCode: "tokenMissing", message: "The JSON Web Token is missing. This means the user is not logged in or the token is invalid." };
            if (error) {
                if (this.debug)
                    console.warn(`[CENTRALAUTH DEBUG] Data check failed for client ${this.clientId || "CentralAuth"} in ${action}: ${error.message}`);
                throw new ValidationError(error);
            }
        };
        //Private method to populate the token, either from the cookie of the token bearer in the headers
        this.populateToken = (headers) => __awaiter(this, void 0, void 0, function* () {
            const authHeader = headers.get("Authorization");
            if (authHeader)
                yield this.setTokenFromTokenBearer(headers);
            else
                yield this.setTokenFromCookie(headers);
        });
        //Private method to get the decoded token
        //Can only be used after the token has been set in this object
        this.getDecodedToken = () => __awaiter(this, void 0, void 0, function* () {
            this.checkData("callback");
            try {
                //Decode the JWT
                const textEncoder = new TextEncoder();
                const { payload: decodedToken } = yield jwtDecrypt(this.token, textEncoder.encode(this.secret));
                return decodedToken;
            }
            catch (error) {
                if (this.debug)
                    console.warn(`[CENTRALAUTH DEBUG] Failed to decode token for client ${this.clientId || "CentralAuth"}: ${error.message}`);
                throw new ValidationError({ errorCode: error === null || error === void 0 ? void 0 : error.name, message: error === null || error === void 0 ? void 0 : error.message });
            }
        });
        //Private method to set the payload of the JWT
        // private setToken = async (payload: JWTPayload) => {
        //   const textEncoder = new TextEncoder();
        //   this.token = await new EncryptJWT(payload)
        //     .setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512" })
        //     .setIssuedAt()
        //     .encrypt(textEncoder.encode(this.secret));
        // }
        //Private method to get the returnTo URL from the config object or current request
        this.getReturnToURL = (req, config) => {
            const url = new URL(req.url);
            const returnToParam = url.searchParams.get("return_to");
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
                if (referrer && !referrer.startsWith("about") && referrer != this.authBaseUrl)
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
        //Private method to get the user data from the ID token or the CentralAuth server
        //Will throw an error when the request fails
        this.getUser = (headers) => __awaiter(this, void 0, void 0, function* () {
            if (this.userData)
                return this.userData;
            else {
                //Get the decoded token
                const jwtPayload = yield this.getDecodedToken();
                const { user } = jwtPayload;
                //Get the IP address and user agent from the headers
                const ipAddress = this.getIPAddress(headers);
                const userAgent = this.getUserAgent(headers);
                this.checkData("user");
                if (this.unsafeIncludeUser && user)
                    this.userData = user;
                else {
                    //Get the user and session data from the CentralAuth server
                    const headers = new Headers();
                    headers.set("Content-Type", "text/plain");
                    headers.set("Authorization", `Basic ${Buffer.from(`${this.clientId || ""}:${this.secret}`).toString("base64")}`);
                    //Set the user agent to the user agent of the current request
                    headers.set("user-agent", userAgent);
                    //Set the custom auth-ip header with the IP address of the current request
                    headers.set("auth-ip", ipAddress);
                    //Construct the URL
                    const requestUrl = new URL(`${this.authBaseUrl}/api/v1/userinfo`);
                    const callbackUrl = new URL(this.callbackUrl);
                    requestUrl.searchParams.set("domain", callbackUrl.origin);
                    const response = yield fetch(requestUrl.toString(), {
                        method: "POST",
                        body: this.token,
                        headers
                    });
                    if (!response.ok) {
                        const error = yield response.json();
                        if (this.debug)
                            console.warn(`[CENTRALAUTH DEBUG] Failed to fetch user data from the server for client ${this.clientId || "CentralAuth"}: ${error.message}`);
                        throw new ValidationError(error);
                    }
                    this.userData = (yield response.json());
                }
            }
        });
        //Private method to populate the token argument from the cookie in the session
        this.setTokenFromCookie = (headers) => __awaiter(this, void 0, void 0, function* () {
            const cookies = parseCookie(headers.get("cookie"));
            //Check for a accessToken or idToken in the cookies based on the unsafeIncludeUser flag
            if (this.unsafeIncludeUser && cookies["idToken"])
                this.token = cookies["idToken"];
            else
                this.token = cookies["accessToken"];
        });
        //Private method to populate the token argument from the JWT in the token bearer header
        this.setTokenFromTokenBearer = (headers) => __awaiter(this, void 0, void 0, function* () {
            const authHeader = headers.get("Authorization");
            //Check for a token bearer header
            if (authHeader && authHeader.startsWith("Bearer "))
                this.token = authHeader.substring(7);
        });
        //Public method to get the user data from the current request headers
        //The JWT will be set based on the cookie or token bearer in the request header
        //Will throw an error when the request fails or the token could not be decoded
        this.getUserData = (headers) => __awaiter(this, void 0, void 0, function* () {
            //Get the user data from cache or CentralAuth
            yield this.populateToken(headers);
            yield this.getUser(headers);
            return this.userData || null;
        });
        //Public method to get an HTML snippet for embedding the login form
        //The login form will be embedded in an iframe with the given login URL
        this.getEmbedScript = (loginPath, returnPath) => {
            const callbackUrl = new URL(this.callbackUrl);
            const srcUrl = new URL(`${callbackUrl.origin}${loginPath}`);
            srcUrl.searchParams.set("embed", "1");
            //Construct the return URL and set it in the src URL
            const returnUrl = new URL(`${callbackUrl.origin}${returnPath}`);
            srcUrl.searchParams.set("return_to", returnUrl.toString());
            const script = `const iframe = document.createElement("iframe");
iframe.id = "centralauth-embedded-login";
iframe.scrolling = "no";
iframe.src = "${srcUrl.toString()}";
iframe.allow = "publickey-credentials-get *; publickey-credentials-create *";
iframe.referrerpolicy = "origin";
iframe.style = "width:420px;outline:none;border:none";
document.getElementById("centralauth-login-form").innerHTML = iframe.outerHTML;
window.addEventListener("message", ({data}) => document.getElementById("centralauth-embedded-login").style.height = data + "px");`;
            return script;
        };
        //Public method to start a direct authentication procedure based on a given email address
        //Will throw an error when the procedure could not be started
        this.authenticateDirect = (req, config) => __awaiter(this, void 0, void 0, function* () {
            this.checkData("login");
            const returnTo = this.getReturnToURL(req, config);
            const callbackUrl = new URL(this.callbackUrl);
            if (returnTo)
                callbackUrl.searchParams.set("return_to", returnTo);
            //Set the body for the direct authentication request
            const body = {
                email: config.email,
                state: config.state || crypto.randomUUID(),
                redirect_uri: callbackUrl.toString(),
                translations: config.translations
            };
            //Set the headers for the direct authentication request
            const headers = new Headers();
            headers.set("Content-Type", "application/json");
            headers.set("Authorization", `Basic ${Buffer.from(`${this.clientId || ""}:${this.secret}`).toString("base64")}`);
            const authenticationResponse = yield fetch(`${this.authBaseUrl}/api/v1/authenticate_direct`, {
                method: "POST",
                body: JSON.stringify(body),
                headers
            });
            if (!authenticationResponse.ok) {
                const error = yield authenticationResponse.json();
                throw new ValidationError(error);
            }
            const responseData = yield authenticationResponse.json();
            return responseData;
        });
        //Public method to start the login procedure
        //Will throw an error when the procedure could not be started
        this.login = (req, config) => __awaiter(this, void 0, void 0, function* () {
            this.checkData("login");
            const returnTo = this.getReturnToURL(req, config);
            const callbackUrl = new URL(this.callbackUrl);
            if (returnTo)
                callbackUrl.searchParams.set("return_to", returnTo);
            //Construct the base URL for the OAuth login
            const authorizationUriParams = {
                redirect_uri: callbackUrl.toString()
            };
            //Add the client ID when given
            if (this.clientId)
                authorizationUriParams.client_id = this.clientId;
            //Add the response type, which is always "code"
            authorizationUriParams.response_type = "code";
            //Add an error message when given
            if (config === null || config === void 0 ? void 0 : config.errorMessage)
                authorizationUriParams.error_message = config.errorMessage;
            //Add a default email address when given
            if (config === null || config === void 0 ? void 0 : config.email)
                authorizationUriParams.email = config.email;
            //Add OAuth state when given, otherwise fall back to a random state
            authorizationUriParams.state = (config === null || config === void 0 ? void 0 : config.state) || crypto.randomUUID();
            //Add translations when given
            if (config === null || config === void 0 ? void 0 : config.translations)
                authorizationUriParams.translations = Buffer.from(JSON.stringify(config.translations)).toString("base64");
            //Add embed boolean when given
            if (config === null || config === void 0 ? void 0 : config.embed)
                authorizationUriParams.embed = "1";
            const authorizationUri = new URL(`${this.authBaseUrl}/login`);
            //Set the search parameters for the authorization URI
            for (const [key, value] of Object.entries(authorizationUriParams))
                authorizationUri.searchParams.set(key, value);
            if (this.debug)
                console.log(`[CENTRALAUTH DEBUG] Starting login procedure for client ${this.clientId || "CentralAuth"}, redirecting to ${authorizationUri.toString()}.`);
            //Redirect to the authorization URI
            return Response.redirect(authorizationUri.toString());
        });
        //Public method for the callback procedure when returning from CentralAuth
        this.callback = (req, config) => __awaiter(this, void 0, void 0, function* () {
            const res = yield this.processCallback(req, config === null || config === void 0 ? void 0 : config.onStateReceived);
            //When an onAfterCallback function is given, call it with the user data
            //The onAfterCallback function may return a new/altered response, which will be returned instead of the default response object
            let callbackResponse = null;
            if (config === null || config === void 0 ? void 0 : config.onAfterCallback)
                callbackResponse = yield config.onAfterCallback(req, res, this.userData);
            //Set a cookie with the JWT and redirect to the returnTo URL
            return callbackResponse || res;
        });
        //Protected method for processing the callback
        //This method will process the OAuth code and verify the user session with it
        //The user object will be retrieved based on the returned access JWT
        //Optionally calls a custom callback function when given with the user object as an argument
        //Returns a Response with a redirection to the returnTo URL
        //Will throw an error when the verification procedure fails or the user object could not be fetched
        this.processCallback = (req, onStateReceived) => __awaiter(this, void 0, void 0, function* () {
            const url = new URL(req.url);
            const searchParams = url.searchParams;
            const returnTo = searchParams.get("return_to") || url.origin;
            const code = searchParams.get("code");
            const state = searchParams.get("state");
            const errorCode = searchParams.get("error_code");
            const errorMessage = searchParams.get("error_message");
            //If the state is given and an onStateReceived function is given, call it to verify the state
            if (state && onStateReceived) {
                const stateVerification = yield onStateReceived(req, state);
                if (!stateVerification) {
                    if (this.debug)
                        console.warn(`[CENTRALAUTH DEBUG] State verification failed for client ${this.clientId || "CentralAuth"}`);
                    throw new ValidationError({ errorCode: "stateInvalid", message: "State verification failed." });
                }
            }
            if (errorCode || errorMessage) {
                //When the error code is set, something went wrong in the login procedure
                //Throw a ValidationError
                if (this.debug)
                    console.warn(`[CENTRALAUTH DEBUG] Error in login procedure for client ${this.clientId || "CentralAuth"}: ${errorMessage}`);
                throw new ValidationError({ errorCode: errorCode, message: errorMessage || "" });
            }
            if (!code) {
                if (this.debug)
                    console.warn(`[CENTRALAUTH DEBUG] Callback could not be processed for client ${this.clientId || "CentralAuth"}, missing code.`);
                throw new ValidationError({ errorCode: "missingFields", message: "The code is missing in the callback URL." });
            }
            const [sessionId, verificationState] = code.split("|");
            if (!sessionId || !verificationState) {
                if (this.debug)
                    console.warn(`[CENTRALAUTH DEBUG] Callback could not be processed for client ${this.clientId || "CentralAuth"}, missing session ID and/or verification state.`);
                throw new ValidationError({ errorCode: "missingFields", message: "The session ID and/or verification state are missing in the callback URL." });
            }
            //Get an access JWT based on the given code
            const headers = new Headers();
            headers.set("Authorization", `Basic ${Buffer.from(`${this.clientId || ""}:${this.secret}`).toString("base64")}`);
            const formData = new FormData();
            formData.append("code", code);
            formData.append("redirect_uri", this.callbackUrl);
            const tokenObject = yield fetch(`${this.authBaseUrl}/api/v1/verify`, {
                method: "POST",
                body: formData,
                headers
            });
            if (!tokenObject.ok) {
                const error = yield tokenObject.json();
                throw new ValidationError(error);
            }
            //Parse the token response
            const tokenResponse = yield tokenObject.json();
            //Set the token in this object based on the unsafeIncludeUser flag
            this.token = this.unsafeIncludeUser ? tokenResponse.id_token : tokenResponse.access_token;
            //Populate the user data based on the token
            yield this.getUser(req.headers);
            //Set the default response object
            let res = new Response(null, {
                status: 302,
                headers: {
                    "Location": returnTo,
                    "Set-Cookie": `${this.unsafeIncludeUser ? "idToken" : "accessToken"}=${this.token}; Path=/; HttpOnly; Max-Age=${tokenResponse.expires_in || 100000000}; SameSite=Lax; Secure`
                }
            });
            //Set a cookie with the JWT and redirect to the returnTo URL
            return res;
        });
        //Public method to get the user data from the current request
        //This method wraps getUserData and returns a Response with the user data as JSON in the body
        //Will return a NULL response on error
        this.user = (req) => __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = req.headers;
                yield this.getUserData(headers);
                //Return the user data as JSON
                return Response.json(this.userData);
            }
            catch (error) {
                //When an error occurs, assume the user session is not valid anymore
                //Delete the cookie
                if (this.debug)
                    console.warn(`[CENTRALAUTH DEBUG] Error fetching user data from cache or CentralAuth server or validation error for client ${this.clientId || "CentralAuth"}: ${error === null || error === void 0 ? void 0 : error.message}`);
                return Response.json(null, {
                    headers: {
                        "Set-Cookie": `${this.unsafeIncludeUser ? "idToken" : "accessToken"}= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure`
                    }
                });
            }
        });
        //Public method to logout
        this.logout = (req, config) => __awaiter(this, void 0, void 0, function* () {
            const returnTo = this.getReturnToURL(req, config);
            const headerList = req.headers;
            try {
                if (config === null || config === void 0 ? void 0 : config.logoutSessionWide) {
                    //Populate the token in this object
                    yield this.populateToken(headerList);
                    //To log out session wide, invalidate the session at CentralAuth
                    const headers = new Headers();
                    headers.set("Content-Type", "text/plain");
                    headers.set("Authorization", `Basic ${Buffer.from(`${this.clientId || ""}:${this.secret}`).toString("base64")}`);
                    const logoutResponse = yield fetch(`${this.authBaseUrl}/api/v1/logout`, {
                        method: "POST",
                        body: this.token,
                        headers
                    });
                    if (!logoutResponse.ok) {
                        const error = yield logoutResponse.json();
                        throw new ValidationError(error);
                    }
                }
            }
            catch (error) {
                if (this.debug)
                    console.warn(`[CENTRALAUTH DEBUG] Error logging out session-wide for client ${this.clientId || "CentralAuth"}: ${error === null || error === void 0 ? void 0 : error.message}`);
            }
            finally {
                //Unset the cookie and redirect to the returnTo URL
                return new Response(null, {
                    status: 302,
                    headers: {
                        "Location": returnTo,
                        "Set-Cookie": `${this.unsafeIncludeUser ? "idToken" : "accessToken"}= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure`
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
        this.debug = debug;
        if (unsafeIncludeUser) {
            this.unsafeIncludeUser = true;
            console.warn(`[CENTRALAUTH DEBUG] Unsafe ID token will be used for ${clientId || "CentralAuth"}.`);
        }
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
        //Overloaded method for direct authentication
        this.authenticateDirectHTTP = (req, config) => __awaiter(this, void 0, void 0, function* () {
            return yield this.authenticateDirect(this.httpRequestToFetchRequest(req), config);
        });
        //Overloaded method for login
        this.loginHTTP = (req, res, config) => __awaiter(this, void 0, void 0, function* () {
            const fetchResponse = yield this.login(this.httpRequestToFetchRequest(req), config);
            yield this.fetchResponseToHttpResponse(fetchResponse, res);
        });
        //Overloaded method for callback
        this.callbackHTTP = (req, res, config) => __awaiter(this, void 0, void 0, function* () {
            const fetchResponse = yield this.processCallback(this.httpRequestToFetchRequest(req), config === null || config === void 0 ? void 0 : config.onStateReceived);
            //When an onAfterCallback function is given, call it with the user data
            //The onAfterCallback function may return a new/altered response, which will be returned instead of the default response object
            let callbackResponse = null;
            if (config === null || config === void 0 ? void 0 : config.onAfterCallback)
                callbackResponse = yield config.onAfterCallback(req, res, fetchResponse, this.userData);
            yield this.fetchResponseToHttpResponse(callbackResponse || fetchResponse, res);
        });
        //Overloaded method for logout
        this.logoutHTTP = (req, res, config) => __awaiter(this, void 0, void 0, function* () {
            const fetchResponse = yield this.logout(this.httpRequestToFetchRequest(req), config);
            yield this.fetchResponseToHttpResponse(fetchResponse, res);
        });
        //Overloaded method for user
        this.userHTTP = (req, res) => __awaiter(this, void 0, void 0, function* () {
            const fetchResponse = yield this.user(this.httpRequestToFetchRequest(req));
            yield this.fetchResponseToHttpResponse(fetchResponse, res);
        });
    }
}
//# sourceMappingURL=server.js.map