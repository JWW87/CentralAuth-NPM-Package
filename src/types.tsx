import { IncomingMessage, ServerResponse } from "http";
import type { ComponentType, FC, ReactElement } from "react";

//Type for the class constructor
export type ConstructorParams = {
  clientId: string | null;
  secret: string;
  authBaseUrl: string;
  callbackUrl: string;
  debug?: boolean;
  unsafeIncludeUser?: boolean;
}

//Type for the user data
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
}

//Type for the payload of the JWT
export type JWTPayload = {
  sessionId: string;
  user?: User;
}

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
}>

//Type for the parameters of the login method
export type LoginParams = {
  returnTo?: string | null;
  email?: string | null;
  state?: string;
  errorMessage?: string | null;
  translations?: Translations | null;
  embed?: boolean | null;
}

//Type for the parameters of the direct authentication method
export type DirectAuthenticationParams = {
  email: string;
  state?: string;
  returnTo?: string | null;
  translations?: Translations | null;
}

//Type for the response of the direct authentication method
export type DirectAuthenticationResponse = {
  loginAttemptId?: string;
  token?: string;
  sentence?: string;
  allowedDate?: string;
};

//Type for the parameters of the logout method
export type LogoutParams = {
  returnTo?: string | null;
  logoutSessionWide?: boolean;
}

//Type for the parameters of the callback method
export type CallbackParams = {
  onStateReceived?: (req: Request, state: string) => Promise<boolean>;
  onAfterCallback?: (req: Request, res: Response, user: User) => Promise<Response | void>;
}

//Type for the parameters of the callback HTTP method
//The originalResponse is the HTTP response object
//The responseToReturn is the Response object that will be sent back to the user. This object can be altered in the callback method and returned to alter the Response that will be returned by the callback function.
export type CallbackParamsHTTP = {
  onStateReceived?: (req: Request, state: string) => Promise<boolean>;
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
  "stateMissing" |
  "stateInvalid" |
  "captchaInvalid";

//Type for the validation errors
export type ErrorObject = {
  errorCode: ErrorCode;
  message?: string;
}

export type TokenResponse = {
  access_token: string;
  id_token: string;
  expires_in: number | null;
  expires_at: string | null;
}

export type WithCentralAuthAutomaticLogin = <T extends { [key: string]: any }>(
  Component: ComponentType<T>,
  config?: Pick<BasePaths, "loginPath" | "profilePath"> & { PlaceholderComponent: ReactElement<any, any> }
) => FC<T>;