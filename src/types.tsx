import { IncomingMessage, ServerResponse } from "http";
import type { ComponentType, FC, ReactElement } from "react";

//Type for the class constructor
export type ConstructorParams = {
  clientId: string | null;
  secret: string;
  authBaseUrl: string;
  callbackUrl: string;
}

//Type for the user data
export type User = {
  id: string;
  email: string;
  gravatar: string | null;
  verified: boolean;
  blocked: boolean;
  organizationId: string | null;
  created: Date;
  updated: Date;
}

//Type for the user data response from CentralAuth
export type UserResponse = {
  user: User;
  session: {
    id: string;
    ipAddress: string;
    userAgent: string;
    lastSync: string;
  }
}

//Type for the payload of the JWT
export type JWTPayload = {
  sessionId: string,
  verificationState: string
} & Partial<UserResponse>;

//Type for the base paths
export type BasePaths = {
  loginPath?: string;
  logoutPath?: string;
  profilePath?: string;
}

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
  loginPageCaptchaText: string;
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
}>

//Type for the parameters of the login method
export type LoginParams = {
  returnTo?: string | null;
  errorMessage?: string | null;
  emailAddress?: string | null;
  translations?: Translations | null;
  embed?: boolean | null;
}

//Type for the parameters of the logout method
export type LogoutParams = {
  returnTo?: string | null;
  LogoutSessionWide?: boolean
}

//Type for the parameters of the callback method
export type CallbackParams = {
  onAfterCallback?: (req: Request, res: Response, user: User) => Promise<Response | void>;
}

//Type for the parameters of the callback HTTP method
//The originalResponse is the HTTP response object
//The responseToReturn is the Response object that will be sent back to the user. This object can be altered in the callback method and returned to alter the Response that will be returned by the callback function.
export type CallbackParamsHTTP = {
  onAfterCallback?: (req: IncomingMessage, originalResponse: ServerResponse, responseToReturn: Response, user: User) => Promise<Response | void>;
}

//Enum for the different error messages
export type ErrorCode = "genericError" |
  "missingFields" |
  "sessionMissing" |
  "sessionNotVerified" |
  "sessionInactive" |
  "sessionInvalid" |
  "domainInvalid" |
  "verificationStateInvalid" |
  "loginAttemptMissing" |
  "loginAttemptExpired" |
  "loginAttemptInvalid" |
  "sessionExpired" |
  "callbackUrlInvalid" |
  "connectionMissing" |
  "organizationIdMissing" |
  "secretMissing" |
  "authBaseUrlMissing" |
  "callbackUrlMissing" |
  "tokenMissing" |
  "tokenInvalid" |
  "captchaInvalid";

//Type for the validation errors
export type ErrorObject = {
  errorCode: ErrorCode;
  message?: string;
}

export type WithCentralAuthAutomaticLogin = <T extends { [key: string]: any }>(
  Component: ComponentType<T>,
  config?: Pick<BasePaths, "loginPath" | "profilePath"> & { PlaceholderComponent: ReactElement<any, any> }
) => FC<T>;