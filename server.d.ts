import { IncomingMessage, ServerResponse } from "http";
import { CallbackParams, ConstructorParams, ErrorObject, LoginParams, LogoutParams, User } from "./types";
export declare class ValidationError extends Error {
    private errorCode;
    constructor(error: ErrorObject);
}
export declare class CentralAuthClass {
    private clientId;
    private secret;
    protected authBaseUrl: string;
    protected callbackUrl: string;
    private token?;
    private user?;
    constructor({ clientId, secret, authBaseUrl, callbackUrl }: ConstructorParams);
    private checkData;
    private getDecodedToken;
    private getReturnToURL;
    private getUserAgent;
    private getIPAddress;
    private getUser;
    private setTokenFromCookie;
    getUserData: (headers: Headers) => Promise<User | null>;
    login: (req: Request, config?: LoginParams) => Promise<Response>;
    callback: (req: Request, config?: CallbackParams) => Promise<Response>;
    me: (req: Request) => Promise<Response>;
    logout: (req: Request, config?: LogoutParams) => Promise<Response>;
}
export declare class CentralAuthHTTPClass extends CentralAuthClass {
    private httpRequestToFetchRequest;
    private fetchResponseToHttpResponse;
    getUserDataHTTP: (req: IncomingMessage) => Promise<User | null>;
    loginHTTP: (req: IncomingMessage, res: ServerResponse, config?: LoginParams) => Promise<void>;
    callbackHTTP: (req: IncomingMessage, res: ServerResponse, config?: CallbackParams) => Promise<void>;
    logoutHTTP: (req: IncomingMessage, res: ServerResponse, config?: LogoutParams) => Promise<void>;
    meHTTP: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
}
