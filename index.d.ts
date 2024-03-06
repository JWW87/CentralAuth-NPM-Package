/// <reference types="node" />
import { IncomingMessage, ServerResponse } from "http";
export type ConstructorParams = {
    organizationId: string | null;
    secret: string;
    authBaseUrl: string;
    callbackUrl: string;
    cacheUserData?: boolean;
};
export type User = {
    id: string;
    email: string;
    verified: boolean;
    blocked: boolean;
    organizationId: string | null;
    created: Date;
    updated: Date;
};
export type JWTPayload = {
    sessionId: string;
    verificationState: string;
    user?: User;
};
export type BasePaths = {
    loginPath?: string;
    logoutPath?: string;
    profilePath?: string;
};
export type Translations = Partial<{
    emailAddress: string;
    loginpageIntro: string;
    loginPagePasskeyAuthentication: string;
    loginPagePasskeyRegistration: string;
    loginPagePasskeyIntro: string;
    loginPagePasskeyOrganizationWarning: string;
    loginPagePasskeyError: string;
    loginpageEmailIntro: string;
    loginPageEmailError: string;
    loginPageCaptcha: string;
    loginPageCaptchaError: string;
    emailLinkSubject: string;
    emailCodeSubject: string;
    emailLinkBody: string;
    emailCodeBody: string;
    emailWaitUntil: string;
    emailBodyWarning: string;
    emailChallengeText: string;
    login: string;
    loginWithPasskey: string;
    loginLocal: string;
    loginRemote: string;
    loginAttemptBody: string;
    loginAttemptCodeBody: string;
    loginAttemptSuccess: string;
    loginAttemptError: string;
    undo: string;
}>;
export type LoginParams = {
    returnTo?: string | null;
    errorMessage?: string | null;
    emailAddress?: string | null;
    translations?: Translations | null;
};
export type LogoutParams = {
    returnTo?: string | null;
    LogoutSessionWide?: boolean;
};
export type CallbackParams = {
    callback?: (req: Request, res: Response, user: User) => Promise<Response | void>;
};
export type ErrorCode = "genericError" | "missingFields" | "sessionMissing" | "sessionNotVerified" | "sessionInactive" | "sessionInvalid" | "domainInvalid" | "verificationStateInvalid" | "loginAttemptMissing" | "loginAttemptExpired" | "loginAttemptInvalid" | "sessionExpired" | "callbackUrlInvalid" | "connectionMissing" | "organizationIdMissing" | "secretMissing" | "authBaseUrlMissing" | "callbackUrlMissing" | "tokenMissing" | "tokenInvalid" | "captchaInvalid";
export type ErrorObject = {
    errorCode: ErrorCode;
    message?: string;
};
export declare class ValidationError extends Error {
    private errorCode;
    constructor(error: ErrorObject);
}
export declare class CentralAuthClass {
    private organizationId;
    private secret;
    private authBaseUrl;
    private callbackUrl;
    private cacheUserData;
    private token?;
    private user?;
    constructor({ organizationId, secret, authBaseUrl, callbackUrl, cacheUserData }: ConstructorParams);
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
