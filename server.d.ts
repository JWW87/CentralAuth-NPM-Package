import { IncomingMessage, ServerResponse } from "http";
import { CallbackParams, CallbackParamsHTTP, ConstructorParams, ErrorObject, LoginParams, LogoutParams, User } from "./src/types";
export declare class ValidationError extends Error {
  private errorCode;
  constructor(error: ErrorObject);
}
export declare class CentralAuthClass {
  private clientId;
  private secret;
  protected authBaseUrl: string;
  protected callbackUrl: string;
  private debug?;
  private unsafeIncludeUser?;
  private token?;
  protected userData?: User;
  constructor({ clientId, secret, authBaseUrl, callbackUrl, debug, unsafeIncludeUser }: ConstructorParams);
  private getOAuthClient;
  private checkData;
  private populateToken;
  private getDecodedToken;
  private getReturnToURL;
  private getUserAgent;
  private getIPAddress;
  private getUser;
  private setTokenFromCookie;
  private setTokenFromTokenBearer;
  getUserData: (headers: Headers) => Promise<User | null>;
  login: (req: Request, config?: LoginParams) => Promise<Response>;
  callback: (req: Request, config?: CallbackParams) => Promise<Response>;
  protected processCallback: (req: Request, onStateReceived?: CallbackParams["onStateReceived"]) => Promise<Response>;
  user: (req: Request) => Promise<Response>;
  logout: (req: Request, config?: LogoutParams) => Promise<Response>;
}
export declare class CentralAuthHTTPClass extends CentralAuthClass {
  private httpRequestToFetchRequest;
  private fetchResponseToHttpResponse;
  getUserDataHTTP: (req: IncomingMessage) => Promise<User | null>;
  loginHTTP: (req: IncomingMessage, res: ServerResponse, config?: LoginParams) => Promise<void>;
  callbackHTTP: (req: IncomingMessage, res: ServerResponse, config?: CallbackParamsHTTP) => Promise<void>;
  logoutHTTP: (req: IncomingMessage, res: ServerResponse, config?: LogoutParams) => Promise<void>;
  userHTTP: (req: IncomingMessage, res: ServerResponse) => Promise<void>;
}
