import { IncomingMessage, ServerResponse } from "http";
import type { ComponentType, FC, ReactElement } from "react";
export type ConstructorParams = {
    clientId: string | null;
    secret: string;
    authBaseUrl: string;
    callbackUrl: string;
    debug?: boolean;
    unsafeIncludeUser?: boolean;
};
export type User = {
    id: string;
    email: string;
    gravatar: string;
    verified: boolean;
    blocked: boolean;
    organizationId: string | null;
    created: Date;
    updated: Date;
    lastLogin: Date | null;
};
export type JWTPayload = {
    sessionId: string;
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
    loginPageCaptchaChallengeText: string;
    loginPageCaptchaPuzzleText: string;
    loginPageCaptchaLockText: string;
    loginPageCaptchaError: string;
    suspiciousActivityDetected: string;
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
    email?: string | null;
    state?: string;
    errorMessage?: string | null;
    translations?: Translations | null;
    embed?: boolean | null;
};
export type DirectAuthenticationParams = {
    email: string;
    state?: string;
    returnTo?: string | null;
    translations?: Translations | null;
};
export type DirectAuthenticationResponse = {
    loginAttemptId?: string;
    token?: string;
    sentence?: string;
    allowedDate?: string;
};
export type LogoutParams = {
    returnTo?: string | null;
    logoutSessionWide?: boolean;
};
export type CallbackParams = {
    onStateReceived?: (req: Request, state: string) => Promise<boolean>;
    onAfterCallback?: (req: Request, res: Response, user: User) => Promise<Response | void>;
};
export type CallbackParamsHTTP = {
    onStateReceived?: (req: Request, state: string) => Promise<boolean>;
    onAfterCallback?: (req: IncomingMessage, originalResponse: ServerResponse, responseToReturn: Response, user: User) => Promise<Response | void>;
};
export type ErrorCode = "genericError" | "noPermission" | "tooManyRequests" | "missingFields" | "sessionMissing" | "sessionNotVerified" | "sessionExpired" | "sessionInactive" | "sessionInvalid" | "domainInvalid" | "verificationStateInvalid" | "loginAttemptMissing" | "loginAttemptExpired" | "loginAttemptInvalid" | "passkeyDataMissing" | "passkeyDataExpired" | "passkeyDataInvalid" | "passkeyWrongOrganization" | "callbackUrlInvalid" | "connectionMissing" | "organizationIdMissing" | "callbackUrlMissing" | "tokenMissing" | "tokenInvalid" | "stateMissing" | "stateInvalid" | "captchaInvalid" | "entityMissing" | "entityInvalid" | "secretMissing" | "authBaseUrlMissing";
export type ErrorObject = {
    errorCode: ErrorCode;
    message?: string;
};
export type TokenResponse = {
    access_token: string;
    id_token: string;
    expires_in: number | null;
    expires_at: string | null;
};
export type WithCentralAuthAutomaticLogin = <T extends {
    [key: string]: any;
}>(Component: ComponentType<T>, config?: Pick<BasePaths, "loginPath" | "profilePath"> & {
    PlaceholderComponent: ReactElement<any, any>;
}) => FC<T>;
