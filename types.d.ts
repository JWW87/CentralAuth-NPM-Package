import { IncomingMessage, ServerResponse } from "http";
import type { ComponentType, FC, ReactElement } from "react";
export type ConstructorParams = {
    clientId: string | null;
    secret: string;
    authBaseUrl: string;
    callbackUrl: string;
    cache?: ExperimentalCacheOptions;
    debug?: boolean;
};
export type ExperimentalCacheOptions = {
    enabled: boolean;
    cacheLifeTime: number;
    cacheHijackProtection?: boolean;
};
export type User = {
    id: string;
    email: string;
    gravatar: string | null;
    verified: boolean;
    blocked: boolean;
    organizationId: string | null;
    created: Date;
    updated: Date;
};
export type UserResponse = {
    user: User;
    session: {
        ipAddress: string;
        userAgent: string;
        lastSync: string;
    };
};
export type JWTPayload = {
    sessionId: string;
} & Partial<UserResponse>;
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
    loginPageCaptchaChallengeText: string;
    loginPageCaptchaPuzzleText: string;
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
    email?: string | null;
    state?: string;
    translations?: Translations | null;
    embed?: boolean | null;
};
export type LogoutParams = {
    returnTo?: string | null;
    LogoutSessionWide?: boolean;
};
export type CallbackParams = {
    onStateReceived?: (req: Request, state: string) => Promise<boolean>;
    onAfterCallback?: (req: Request, res: Response, user: User) => Promise<Response | void>;
};
export type CallbackParamsHTTP = {
    onStateReceived?: (req: Request, state: string) => Promise<boolean>;
    onAfterCallback?: (req: IncomingMessage, originalResponse: ServerResponse, responseToReturn: Response, user: User) => Promise<Response | void>;
};
export type ErrorCode = "genericError" | "missingFields" | "sessionMissing" | "sessionNotVerified" | "sessionInactive" | "sessionInvalid" | "domainInvalid" | "verificationStateInvalid" | "loginAttemptMissing" | "loginAttemptExpired" | "loginAttemptInvalid" | "sessionExpired" | "callbackUrlInvalid" | "connectionMissing" | "organizationIdMissing" | "secretMissing" | "authBaseUrlMissing" | "callbackUrlMissing" | "tokenMissing" | "tokenInvalid" | "stateMissing" | "stateInvalid" | "captchaInvalid";
export type ErrorObject = {
    errorCode: ErrorCode;
    message?: string;
};
export type WithCentralAuthAutomaticLogin = <T extends {
    [key: string]: any;
}>(Component: ComponentType<T>, config?: Pick<BasePaths, "loginPath" | "profilePath"> & {
    PlaceholderComponent: ReactElement<any, any>;
}) => FC<T>;
