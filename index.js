"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.withCentralAuthAutomaticLogin = exports.useUser = exports.CentralAuthClass = exports.ValidationError = void 0;
var swr_1 = __importDefault(require("swr"));
var react_1 = __importStar(require("react"));
var jwt = require("jsonwebtoken");
//Private method for parsing a cookie string in a request header
var parseCookie = function (cookieString) {
    return ((cookieString === null || cookieString === void 0 ? void 0 : cookieString.split(';').map(function (v) { return v.split('='); }).reduce(function (acc, v) {
        acc[decodeURIComponent(v[0].trim())] = decodeURIComponent(v[1].trim());
        return acc;
    }, {})) || {});
};
//Extension of the Error object to throw a validation error
var ValidationError = /** @class */ (function (_super) {
    __extends(ValidationError, _super);
    function ValidationError(error) {
        var _this = _super.call(this, error.message) || this;
        _this.errorCode = error.errorCode;
        return _this;
    }
    return ValidationError;
}(Error));
exports.ValidationError = ValidationError;
//Class for CentralAuth
var CentralAuthClass = /** @class */ (function () {
    //Constructor method to set all instance variable
    function CentralAuthClass(_a) {
        var organizationId = _a.organizationId, secret = _a.secret, authBaseUrl = _a.authBaseUrl, callbackUrl = _a.callbackUrl, cacheUserData = _a.cacheUserData;
        var _this = this;
        this.cacheUserData = false;
        //Private method to check whether all variable are set for a specific action
        //Will throw a ValidationError when a check fails
        this.checkData = function (action) {
            var error = null;
            if (typeof _this.organizationId === "undefined")
                error = { errorCode: "organizationIdMissing", message: "The organization ID is missing. This ID can be found on the organization page in your admin console." };
            if (!_this.secret)
                error = { errorCode: "secretMissing", message: "The secret is missing. The secret is shown only once at the creation of an organization and should never be exposed publicly or stored unsafely." };
            if (!_this.callbackUrl)
                error = { errorCode: "callbackUrlMissing", message: "The callback URL is missing." };
            if (!_this.authBaseUrl)
                error = { errorCode: "authBaseUrlMissing", message: "The base URL for the organization is missing. The base URL is either the internal base URL or a custom domain for your organization." };
            if ((action == "callback" || action == "verify" || action == "me") && !_this.token)
                error = { errorCode: "tokenMissing", message: "The JSON Web Token is missing. A JWT must be created in the callback after a successful login attempt." };
            if (error)
                throw new ValidationError(error);
        };
        //Private method to get the decoded token
        this.getDecodedToken = function () { return __awaiter(_this, void 0, void 0, function () {
            var decodedToken;
            return __generator(this, function (_a) {
                this.checkData("callback");
                try {
                    decodedToken = jwt.verify(this.token, this.secret);
                    return [2 /*return*/, decodedToken];
                }
                catch (error) {
                    throw new ValidationError({ errorCode: error === null || error === void 0 ? void 0 : error.name, message: error === null || error === void 0 ? void 0 : error.message });
                }
                return [2 /*return*/];
            });
        }); };
        //Private method to get the returnTo URL from the config object or current request
        this.getReturnToURL = function (req, config) {
            var url = new URL(req.url);
            var returnToParam = url.searchParams.get("returnTo");
            var headers = req.headers;
            var returnTo = "";
            //Set returnTo when explicitly given in the config object
            if (config === null || config === void 0 ? void 0 : config.returnTo)
                returnTo = config.returnTo;
            else if (returnToParam)
                returnTo = returnToParam; //Set returnTo to any returnTo query param in the URL
            else {
                var referrer = headers.get("referer");
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
        this.getUserAgent = function (headers) {
            var userAgent = headers.get("user-agent");
            return userAgent || "native";
        };
        //Private method to return the client IP address from request headers
        this.getIPAddress = function (headers) {
            var realIp = headers.get("x-real-ip");
            var forwardedFor = headers.get("x-forwarded-for");
            var ip = realIp || forwardedFor || null;
            //The IP address might consist of multiple IP addresses, seperated by commas. Only return the first IP address
            return ip ? ip.split(",")[0] : "0.0.0.0";
        };
        //Private method to get the user data from the CentralAuth server
        //Will throw an error when the request fails
        this.getUser = function (sessionId, userAgent, ipAddress) { return __awaiter(_this, void 0, void 0, function () {
            var headers, requestUrl, callbackUrl, response, error, _a;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        if (!this.user) return [3 /*break*/, 1];
                        return [2 /*return*/, this.user];
                    case 1:
                        this.checkData("me");
                        headers = new Headers();
                        headers.set("Authorization", "Bearer ".concat(this.token));
                        //Set the user agent to the user agent of the current request
                        headers.set("user-agent", userAgent);
                        //Set the custom auth-ip header with the IP address of the current request
                        headers.set("auth-ip", ipAddress);
                        requestUrl = new URL("".concat(this.authBaseUrl, "/api/v1/me/").concat(sessionId));
                        callbackUrl = new URL(this.callbackUrl);
                        requestUrl.searchParams.set("domain", callbackUrl.origin);
                        return [4 /*yield*/, fetch(requestUrl.toString(), { headers: headers })];
                    case 2:
                        response = _b.sent();
                        if (!!response.ok) return [3 /*break*/, 4];
                        return [4 /*yield*/, response.json()];
                    case 3:
                        error = _b.sent();
                        throw new ValidationError(error);
                    case 4:
                        _a = this;
                        return [4 /*yield*/, response.json()];
                    case 5:
                        _a.user = (_b.sent());
                        _b.label = 6;
                    case 6: return [2 /*return*/];
                }
            });
        }); };
        //Private method to populate the token argument from the cookie in the session
        this.setTokenFromCookie = function (req) { return __awaiter(_this, void 0, void 0, function () {
            var headers, cookies;
            return __generator(this, function (_a) {
                headers = req.headers;
                cookies = parseCookie(headers.get("cookie"));
                //Check for a sessionToken in the cookies
                if (cookies["sessionToken"])
                    this.token = cookies["sessionToken"];
                return [2 /*return*/];
            });
        }); };
        //Public method to get the user data from the current request
        //The JWT will be set based on the sessionToken cookie in the request header
        //Will throw an error when the request fails or the token could not be decoded
        this.getUserData = function (req) { return __awaiter(_this, void 0, void 0, function () {
            var headers, _a, sessionId, user;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        headers = req.headers;
                        //Populate the token
                        return [4 /*yield*/, this.setTokenFromCookie(req)];
                    case 1:
                        //Populate the token
                        _b.sent();
                        return [4 /*yield*/, this.getDecodedToken()];
                    case 2:
                        _a = _b.sent(), sessionId = _a.sessionId, user = _a.user;
                        if (!(this.cacheUserData && user)) return [3 /*break*/, 3];
                        //Get the user data from the cached data in the JWT when available
                        this.user = user;
                        return [3 /*break*/, 5];
                    case 3: 
                    //Get the user data from CentralAuth
                    return [4 /*yield*/, this.getUser(sessionId, this.getUserAgent(headers), this.getIPAddress(headers))];
                    case 4:
                        //Get the user data from CentralAuth
                        _b.sent();
                        _b.label = 5;
                    case 5: return [2 /*return*/, this.user || null];
                }
            });
        }); };
        //Public method to start the login procedure
        //Will throw an error when the procedure could not be started
        this.login = function (req, config) { return __awaiter(_this, void 0, void 0, function () {
            var returnTo, callbackUrl, translations, loginUrl;
            return __generator(this, function (_a) {
                this.checkData("login");
                returnTo = this.getReturnToURL(req, config);
                callbackUrl = new URL(this.callbackUrl);
                if (returnTo)
                    callbackUrl.searchParams.set("returnTo", returnTo);
                translations = (config === null || config === void 0 ? void 0 : config.translations) ? btoa(JSON.stringify(config.translations)) : null;
                loginUrl = new URL("".concat(this.authBaseUrl, "/login"));
                if (this.organizationId)
                    loginUrl.searchParams.set("organizationId", this.organizationId);
                //Add an error message when given
                if (config === null || config === void 0 ? void 0 : config.errorMessage)
                    loginUrl.searchParams.set("errorMessage", config === null || config === void 0 ? void 0 : config.errorMessage);
                //Add translations when given
                if (translations)
                    loginUrl.searchParams.set("translations", translations);
                loginUrl.searchParams.set("callbackUrl", callbackUrl.toString());
                return [2 /*return*/, Response.redirect(loginUrl.toString())];
            });
        }); };
        //Public method for the callback procedure when returning from CentralAuth
        //This method will automatically verify the JWT payload and set the sessionToken cookie
        //Optionally calls a custom callback function when given with the user data as an argument
        //Returns a Response with a redirection to the returnTo URL
        //Will throw an error when the verification procedure fails or the user data could not be fetched
        this.callback = function (req, config) { return __awaiter(_this, void 0, void 0, function () {
            var url, searchParams, returnTo, sessionId, verificationState, errorCode, errorMessage, headers, requestUrl, callbackUrl, verifyResponse, error, _a, res, callbackResponse;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        url = new URL(req.url);
                        searchParams = url.searchParams;
                        returnTo = searchParams.get("returnTo") || url.origin;
                        sessionId = searchParams.get("sessionId");
                        verificationState = searchParams.get("verificationState");
                        errorCode = searchParams.get("errorCode");
                        errorMessage = searchParams.get("errorMessage");
                        if (errorCode) {
                            //When the error code is set, something went wrong in the login procedure
                            //Throw a ValidationError
                            throw new ValidationError({ errorCode: errorCode, message: errorMessage || "" });
                        }
                        //Build the JWT with the session ID and verification state as payload
                        this.token = jwt.sign({ sessionId: sessionId, verificationState: verificationState }, this.secret);
                        this.checkData("callback");
                        headers = new Headers();
                        headers.set("Authorization", "Bearer ".concat(this.token));
                        requestUrl = new URL("".concat(this.authBaseUrl, "/api/v1/verify/").concat(sessionId, "/").concat(verificationState));
                        callbackUrl = new URL(this.callbackUrl);
                        requestUrl.searchParams.set("domain", callbackUrl.origin);
                        return [4 /*yield*/, fetch(requestUrl, { headers: headers })];
                    case 1:
                        verifyResponse = _b.sent();
                        if (!!verifyResponse.ok) return [3 /*break*/, 3];
                        return [4 /*yield*/, verifyResponse.json()];
                    case 2:
                        error = _b.sent();
                        throw new ValidationError(error);
                    case 3:
                        _a = this;
                        return [4 /*yield*/, verifyResponse.json()];
                    case 4:
                        _a.user = (_b.sent());
                        if (this.cacheUserData) {
                            //Add the user data to the JWT
                            this.token = jwt.sign({ sessionId: sessionId, verificationState: verificationState, user: this.user }, this.secret);
                        }
                        res = new Response(null, {
                            status: 302,
                            headers: {
                                "Location": returnTo,
                                "Set-Cookie": "sessionToken=".concat(this.token, "; Path=/; HttpOnly; Max-Age=100000000; SameSite=Strict; Secure")
                            }
                        });
                        callbackResponse = null;
                        if (!(config === null || config === void 0 ? void 0 : config.callback)) return [3 /*break*/, 6];
                        return [4 /*yield*/, config.callback(req, res, this.user)];
                    case 5:
                        callbackResponse = _b.sent();
                        _b.label = 6;
                    case 6: 
                    //Set a cookie with the JWT and redirect to the returnTo URL
                    return [2 /*return*/, callbackResponse || res];
                }
            });
        }); };
        //Public method to get the user data from the current request
        //This method wraps getUserData and returns a Response with the user data as JSON in the body
        //Will return a NULL response on error
        this.me = function (req) { return __awaiter(_this, void 0, void 0, function () {
            var error_1;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        _a.trys.push([0, 2, , 3]);
                        return [4 /*yield*/, this.getUserData(req)];
                    case 1:
                        _a.sent();
                        return [2 /*return*/, Response.json(this.user)];
                    case 2:
                        error_1 = _a.sent();
                        //When an error occurs, assume the user session is not valid anymore
                        //Delete the cookie
                        return [2 /*return*/, Response.json(null, {
                                headers: {
                                    "Set-Cookie": "sessionToken= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict; Secure"
                                }
                            })];
                    case 3: return [2 /*return*/];
                }
            });
        }); };
        //Public method to logout
        this.logout = function (req, config) { return __awaiter(_this, void 0, void 0, function () {
            var returnTo, sessionId, headers, error_2;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        returnTo = this.getReturnToURL(req, config);
                        _a.label = 1;
                    case 1:
                        _a.trys.push([1, 6, 7, 8]);
                        if (!(config === null || config === void 0 ? void 0 : config.LogoutSessionWide)) return [3 /*break*/, 5];
                        //To log out session wide, invalidate the session at CentralAuth
                        return [4 /*yield*/, this.setTokenFromCookie(req)];
                    case 2:
                        //To log out session wide, invalidate the session at CentralAuth
                        _a.sent();
                        return [4 /*yield*/, this.getDecodedToken()];
                    case 3:
                        sessionId = (_a.sent()).sessionId;
                        headers = new Headers();
                        headers.set("Authorization", "Bearer ".concat(this.token));
                        return [4 /*yield*/, fetch("".concat(this.authBaseUrl, "/api/v1/logout/").concat(sessionId), { headers: headers })];
                    case 4:
                        _a.sent();
                        _a.label = 5;
                    case 5: return [3 /*break*/, 8];
                    case 6:
                        error_2 = _a.sent();
                        console.error("Error logging out session-wide", error_2);
                        return [3 /*break*/, 8];
                    case 7: 
                    //Unset the cookie and redirect to the returnTo URL
                    return [2 /*return*/, new Response(null, {
                            status: 302,
                            headers: {
                                "Location": returnTo,
                                "Set-Cookie": "sessionToken= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict; Secure"
                            }
                        })];
                    case 8: return [2 /*return*/];
                }
            });
        }); };
        this.organizationId = organizationId;
        this.secret = secret;
        this.authBaseUrl = authBaseUrl;
        this.callbackUrl = callbackUrl;
        this.cacheUserData = cacheUserData || false;
    }
    return CentralAuthClass;
}());
exports.CentralAuthClass = CentralAuthClass;
//React hook to declaratively get the currently logged in user via SWR. See https://swr.vercel.app for more info on SWR.
//Param basePath can be used when the API route for /me is different from the default /api/auth/me
//Will return null when the user is not logged in or on error, and undefined when the request is still active
//The error object will be populated with the fetcher error when the request failed
var useUser = function (config) {
    var _a = (0, swr_1.default)((config === null || config === void 0 ? void 0 : config.loginPath) || "/api/auth/me", function (resource, init) { return fetch(resource, init).then(function (res) { return res.json(); }); }, {}), user = _a.data, error = _a.error, isLoading = _a.isLoading, isValidating = _a.isValidating;
    return { user: !error ? user : null, error: error, isLoading: isLoading, isValidating: isValidating };
};
exports.useUser = useUser;
//Wrapper for a React based client to redirect an anonymous user to CentralAuth when visiting a page that requires authentication
var withCentralAuthAutomaticLogin = function (Component, config) {
    if (config === void 0) { config = {}; }
    return function withCentralAuthAutomaticLogin(props) {
        var loginPath = config.loginPath, profilePath = config.profilePath;
        var _a = (0, react_1.useState)(), user = _a[0], setUser = _a[1];
        (0, react_1.useEffect)(function () {
            fetch(profilePath || "/api/auth/me")
                .then(function (response) {
                response.json()
                    .then(function (userData) {
                    if (userData == null)
                        window.location.replace(loginPath || "/api/auth/login");
                    else
                        setUser(userData);
                });
            });
        }, [loginPath, profilePath]);
        if (user)
            return react_1.default.createElement(Component, __assign({}, props));
        return null;
    };
};
exports.withCentralAuthAutomaticLogin = withCentralAuthAutomaticLogin;
