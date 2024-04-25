import type { ComponentType, FC, ReactElement } from "react";

//Type for the class constructor
export type ConstructorParams = {
  organizationId: string | null;
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

//Type for the payload of the JWT
export type JWTPayload = {
  sessionId: string,
  verificationState: string
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
  callback?: (req: Request, res: Response, user: User) => Promise<Response | void>;
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