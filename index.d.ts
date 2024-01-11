export type ConstructorParams = {
    organizationId: string | null;
    secret: string;
    authBaseUrl: string;
    callbackUrl: string;
};
export type User = {
    id: string;
    verified: boolean;
    email: string;
    blocked: boolean;
    organizationId: string;
};
export type Translations = {
    emailAddress?: string;
    loginpageIntro?: string;
    loginPageEmailError?: string;
    emailLinkSubject?: string;
    emailLinkBody?: string;
    emailLinkBodyWarning?: string;
    login?: string;
};
export type LoginParams = {
    returnTo?: string;
    translations?: Translations;
};
export type LogoutParams = {
    returnTo?: string;
};
export type CallbackParams = {
    callback?: (user: User) => Promise<void>;
};
export type ErrorCode = "genericError" | "missingFields" | "sessionMissing" | "sessionNotVerified" | "sessionInvalid" | "verificationStateInvalid" | "loginAttemptMissing" | "loginAttemptExpired" | "loginAttemptInvalid" | "sessionExpired" | "callbackUrlInvalid" | "connectionMissing" | "organizationIdMissing" | "secretMissing" | "authBaseUrlMissing" | "callbackUrlMissing" | "tokenMissing" | "tokenInvalid";
export type ErrorObject = {
    errorCode: ErrorCode;
    message?: string;
};
export declare class ValidationError extends Error {
    private errorCode;
    constructor(error: ErrorObject);
}
export declare class CentralAuthClient {
    private organizationId;
    private secret;
    private authBaseUrl;
    private callbackUrl;
    private token?;
    private user?;
    constructor({ organizationId, secret, authBaseUrl, callbackUrl }: ConstructorParams);
    private checkData;
    private getDecodedToken;
    private getReturnToURL;
    private getUserAgent;
    private getIPAddress;
    private getUser;
    getUserData: (req: Request) => Promise<User>;
    login: (req: Request, config?: LoginParams) => Promise<Response>;
    callback: (req: Request, config?: CallbackParams) => Promise<Response>;
    me: (req: Request) => Promise<Response>;
    logout: (req: Request, config?: LogoutParams) => Promise<Response>;
}
export declare const useUser: () => User;
