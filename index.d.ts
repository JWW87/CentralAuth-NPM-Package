import { ComponentType, FC } from "react";
export type ConstructorParams = {
    organizationId: string | null;
    secret: string;
    authBaseUrl: string;
    callbackUrl: string;
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
export type BasePaths = {
    loginPath?: string;
    logoutPath?: string;
    profilePath?: string;
};
export type Translations = Partial<{
    emailAddress: string;
    loginpageIntro: string;
    loginPageEmailError: string;
    emailLinkSubject: string;
    emailCodeSubject: string;
    emailLinkBody: string;
    emailCodeBody: string;
    emailBodyWarning: string;
    emailChallengeText: string;
    login: string;
    loginLocal: string;
    loginRemote: string;
    loginAttemptBody: string;
    loginAttemptCodeBody: string;
    loginAttemptSuccess: string;
    loginAttemptError: string;
}>;
export type LoginParams = {
    returnTo?: string | null;
    errorMessage?: string | null;
    translations?: Translations | null;
};
export type LogoutParams = {
    returnTo?: string | null;
    LogoutSessionWide?: boolean;
};
export type CallbackParams = {
    callback?: (req: Request, res: Response, user: User) => Promise<Response | void>;
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
export declare class CentralAuthClass {
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
    private setTokenFromCookie;
    getUserData: (req: Request) => Promise<User>;
    login: (req: Request, config?: LoginParams) => Promise<Response>;
    callback: (req: Request, config?: CallbackParams) => Promise<Response>;
    me: (req: Request) => Promise<Response>;
    logout: (req: Request, config?: LogoutParams) => Promise<Response>;
}
export declare const useUser: (config?: Pick<BasePaths, "loginPath">) => {
    user: User;
    error: any;
    isLoading: boolean;
    isValidating: boolean;
};
export type WithCentralAuthAutomaticLogin = <T extends {
    [key: string]: any;
}>(Component: ComponentType<T>, config?: Pick<BasePaths, "loginPath" | "profilePath">) => FC<T>;
export declare const withCentralAuthAutomaticLogin: WithCentralAuthAutomaticLogin;
