import useSWR from "swr";
import React, { ComponentType, FC, ReactNode, useEffect, useState } from "react";
const jwt = require("jsonwebtoken");

//Type for the class constructor
export type ConstructorParams = {
  organizationId: string | null;
  secret: string;
  authBaseUrl: string;
  callbackUrl: string;
  cacheUserData?: boolean;
}

//Type for the user data
export type User = {
  id: string;
  email: string;
  verified: boolean;
  blocked: boolean;
  organizationId: string | null;
  created: Date;
  updated: Date;
}

//Type for the payload of the JWT
export type JWTPayload = {
  sessionId: string,
  verificationState: string,
  user?: User
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
}>

//Type for the parameters of the login method
export type LoginParams = {
  returnTo?: string | null;
  errorMessage?: string | null;
  translations?: Translations | null
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
  "sessionInvalid" |
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
  "tokenInvalid";

//Type for the validation errors
export type ErrorObject = {
  errorCode: ErrorCode;
  message?: string;
}

//Private method for parsing a cookie string in a request header
const parseCookie = (cookieString: string | null) =>
  (cookieString?.split(';')
    .map(v => v.split('='))
    .reduce((acc: any, v) => {
      acc[decodeURIComponent(v[0].trim())] = decodeURIComponent(v[1].trim());
      return acc;
    }, {}) || {}) as { [key: string]: string };

//Extension of the Error object to throw a validation error
export class ValidationError extends Error {
  private errorCode: string;

  constructor(error: ErrorObject) {
    super(error.message);
    this.errorCode = error.errorCode;
  }
}

//Class for CentralAuth
export class CentralAuthClass {
  private organizationId: string | null;
  private secret: string;
  private authBaseUrl: string;
  private callbackUrl: string;
  private cacheUserData: boolean = false;
  private token?: string;
  private user?: User;

  //Constructor method to set all instance variable
  constructor({ organizationId, secret, authBaseUrl, callbackUrl, cacheUserData }: ConstructorParams) {
    this.organizationId = organizationId;
    this.secret = secret;
    this.authBaseUrl = authBaseUrl;
    this.callbackUrl = callbackUrl;
    this.cacheUserData = !!cacheUserData;
  }

  //Private method to check whether all variable are set for a specific action
  //Will throw a ValidationError when a check fails
  private checkData = (action: "login" | "callback" | "verify" | "me") => {
    let error: ErrorObject | null = null;
    if (typeof this.organizationId === "undefined")
      error = { errorCode: "organizationIdMissing", message: "The organization ID is missing. This ID can be found on the organization page in your admin console." };
    if (!this.secret)
      error = { errorCode: "secretMissing", message: "The secret is missing. The secret is shown only once at the creation of an organization and should never be exposed publicly or stored unsafely." };
    if (!this.callbackUrl)
      error = { errorCode: "callbackUrlMissing", message: "The callback URL is missing." };
    if (!this.authBaseUrl)
      error = { errorCode: "authBaseUrlMissing", message: "The base URL for the organization is missing. The base URL is either the internal base URL or a custom domain for your organization." };
    if ((action == "callback" || action == "verify" || action == "me") && !this.token)
      error = { errorCode: "tokenMissing", message: "The JSON Web Token is missing. A JWT must be created in the callback after a successful login attempt." };

    if (error)
      throw new ValidationError(error);
  }

  //Private method to get the decoded token
  private getDecodedToken = async () => {
    this.checkData("callback");

    try {
      //Decode the JWT
      const decodedToken = jwt.verify(this.token!, this.secret) as JWTPayload;

      return decodedToken;
    } catch (error: any) {
      throw new ValidationError({ errorCode: error?.name, message: error?.message });
    }
  }

  //Private method to get the returnTo URL from the config object or current request
  private getReturnToURL = (req: Request, config?: LoginParams | LogoutParams) => {
    const url = new URL(req.url);
    const returnToParam = url.searchParams.get("returnTo");
    const headers = req.headers;

    let returnTo = "";
    //Set returnTo when explicitly given in the config object
    if (config?.returnTo)
      returnTo = config.returnTo;
    else if (returnToParam)
      returnTo = returnToParam; //Set returnTo to any returnTo query param in the URL
    else {
      const referrer = headers.get("referer");
      //Set returnTo to the referrer in the request when present
      if (referrer && !referrer.startsWith("about"))
        returnTo = referrer;
      else {
        //Otherwise fallback to the origin
        returnTo = new URL(req.url).origin;
      }
    }

    return returnTo;
  }

  //Private method to return the client user agent from request headers
  private getUserAgent = (headers: Headers) => {
    const userAgent = headers.get("user-agent");
    return userAgent || "native";
  }

  //Private method to return the client IP address from request headers
  private getIPAddress = (headers: Headers) => {
    const realIp = headers.get("x-real-ip");
    const forwardedFor = headers.get("x-forwarded-for");
    const ip = realIp || forwardedFor || null;
    //The IP address might consist of multiple IP addresses, seperated by commas. Only return the first IP address
    return ip ? ip.split(",")[0] : "0.0.0.0";
  }

  //Private method to get the user data from the CentralAuth server
  //Will throw an error when the request fails
  private getUser = async (sessionId: string, userAgent: string, ipAddress: string) => {
    if (this.user)
      return this.user;
    else {
      this.checkData("me");

      const headers = new Headers();
      headers.set("Authorization", `Bearer ${this.token!}`);
      //Set the user agent to the user agent of the current request
      headers.set("user-agent", userAgent);
      //Set the custom auth-ip header with the IP address of the current request
      headers.set("auth-ip", ipAddress);

      //Construct the URL
      const requestUrl = new URL(`${this.authBaseUrl}/api/v1/me/${sessionId}`);
      const callbackUrl = new URL(this.callbackUrl!);
      requestUrl.searchParams.set("domain", callbackUrl.origin);

      const response = await fetch(requestUrl.toString(), { headers });
      if (!response.ok) {
        const error = await response.json() as ErrorObject;
        throw new ValidationError(error);
      }
      this.user = await response.json() as User;
    }
  }

  //Private method to populate the token argument from the cookie in the session
  private setTokenFromCookie = async (req: Request) => {
    const headers = req.headers;
    const cookies = parseCookie(headers.get("cookie"));
    //Check for a sessionToken in the cookies
    if (cookies["sessionToken"])
      this.token = cookies["sessionToken"];
  }

  //Public method to get the user data from the current request
  //The JWT will be set based on the sessionToken cookie in the request header
  //Will throw an error when the request fails or the token could not be decoded
  public getUserData = async (req: Request) => {
    const headers = req.headers;
    //Populate the token
    await this.setTokenFromCookie(req);
    //Decode the token to get the session ID
    const { sessionId, user } = await this.getDecodedToken();

    if (this.cacheUserData && user) {
      //Get the user data from the cached data in the JWT when available
      this.user = user;
    } else {
      //Get the user data from CentralAuth
      await this.getUser(sessionId, this.getUserAgent(headers), this.getIPAddress(headers));
    }

    return this.user || null;
  }

  //Public method to start the login procedure
  //Will throw an error when the procedure could not be started
  public login = async (req: Request, config?: LoginParams) => {
    this.checkData("login");

    const returnTo = this.getReturnToURL(req, config);
    const callbackUrl = new URL(this.callbackUrl);
    if (returnTo)
      callbackUrl.searchParams.set("returnTo", returnTo);

    //Check for custom translations in the config
    const translations = config?.translations ? btoa(JSON.stringify(config.translations)) : null;

    //Redirect to the login page
    const loginUrl = new URL(`${this.authBaseUrl}/login`);
    if (this.organizationId)
      loginUrl.searchParams.set("organizationId", this.organizationId);
    //Add an error message when given
    if (config?.errorMessage)
      loginUrl.searchParams.set("errorMessage", config?.errorMessage);
    //Add translations when given
    if (translations)
      loginUrl.searchParams.set("translations", translations);
    loginUrl.searchParams.set("callbackUrl", callbackUrl.toString());

    return Response.redirect(loginUrl.toString());
  }

  //Public method for the callback procedure when returning from CentralAuth
  //This method will automatically verify the JWT payload and set the sessionToken cookie
  //Optionally calls a custom callback function when given with the user data as an argument
  //Returns a Response with a redirection to the returnTo URL
  //Will throw an error when the verification procedure fails or the user data could not be fetched
  public callback = async (req: Request, config?: CallbackParams) => {
    const url = new URL(req.url);
    const searchParams = url.searchParams;
    const returnTo = searchParams.get("returnTo") || url.origin;
    const sessionId = searchParams.get("sessionId");
    const verificationState = searchParams.get("verificationState");
    const errorCode = searchParams.get("errorCode");
    const errorMessage = searchParams.get("errorMessage");

    if (errorCode) {
      //When the error code is set, something went wrong in the login procedure
      //Throw a ValidationError
      throw new ValidationError({ errorCode: errorCode as ErrorCode, message: errorMessage || "" })
    }

    //Build the JWT with the session ID and verification state as payload
    this.token = jwt.sign({ sessionId, verificationState } as JWTPayload, this.secret);
    this.checkData("callback");

    //Make a request to the verification endpoint to verify this session at CentralAuth
    const headers = new Headers();
    headers.set("Authorization", `Bearer ${this.token}`);

    //Construct the URL
    const requestUrl = new URL(`${this.authBaseUrl}/api/v1/verify/${sessionId}/${verificationState}`);
    const callbackUrl = new URL(this.callbackUrl!);
    requestUrl.searchParams.set("domain", callbackUrl.origin);
    const verifyResponse = await fetch(requestUrl, { headers });
    if (!verifyResponse.ok) {
      const error = await verifyResponse.json() as ErrorObject;
      throw new ValidationError(error);
    }
    this.user = await verifyResponse.json() as User;

    if (this.cacheUserData) {
      //Add the user data to the JWT
      this.token = jwt.sign({ sessionId, verificationState, user: this.user } as JWTPayload, this.secret);
    }

    //Set the default response object
    let res = new Response(null,
      {
        status: 302,
        headers: {
          "Location": returnTo,
          "Set-Cookie": `sessionToken=${this.token}; Path=/; HttpOnly; Max-Age=100000000; SameSite=Strict; Secure`
        }
      }
    );

    //When a callback function is given, call it with the user data
    //The callback function may return a new/altered response, which will be returned instead of the default response object
    let callbackResponse: Response | void | null = null;
    if (config?.callback)
      callbackResponse = await config.callback(req, res, this.user!);

    //Set a cookie with the JWT and redirect to the returnTo URL
    return callbackResponse || res;
  }

  //Public method to get the user data from the current request
  //This method wraps getUserData and returns a Response with the user data as JSON in the body
  //Will return a NULL response on error
  public me = async (req: Request) => {
    try {
      await this.getUserData(req);
      return Response.json(this.user);
    } catch (error) {
      //When an error occurs, assume the user session is not valid anymore
      //Delete the cookie
      return Response.json(null, {
        headers: {
          "Set-Cookie": "sessionToken= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict; Secure"
        }
      })
    }
  }

  //Public method to logout
  public logout = async (req: Request, config?: LogoutParams) => {
    const returnTo = this.getReturnToURL(req, config);

    try {
      if (config?.LogoutSessionWide) {
        if (this.cacheUserData)
          console.warn("Session-wide logging out not supported when caching user data.");

        //To log out session wide, invalidate the session at CentralAuth
        await this.setTokenFromCookie(req);
        //Get the session ID from the token
        const { sessionId } = await this.getDecodedToken();
        //Make a request to the log out endpoint to invalidate this session at CentralAuth
        const headers = new Headers();
        headers.set("Authorization", `Bearer ${this.token}`);
        const logoutResponse = await fetch(`${this.authBaseUrl}/api/v1/logout/${sessionId}`, { headers });
        if (!logoutResponse.ok) {
          const error = await logoutResponse.json() as ErrorObject;
          throw new ValidationError(error);
        }
      }
    } catch (error) {
      console.error("Error logging out session-wide", error);
    } finally {
      //Unset the cookie and redirect to the returnTo URL
      return new Response(null,
        {
          status: 302,
          headers: {
            "Location": returnTo,
            "Set-Cookie": "sessionToken= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Strict; Secure"
          }
        }
      );
    }
  }
}

//React hook to declaratively get the currently logged in user via SWR. See https://swr.vercel.app for more info on SWR.
//Param basePath can be used when the API route for /me is different from the default /api/auth/me
//Will return null when the user is not logged in or on error, and undefined when the request is still active
//The error object will be populated with the fetcher error when the request failed
export const useUser = (config?: Pick<BasePaths, "loginPath">) => {
  const { data: user, error, isLoading, isValidating } = useSWR<User | null>(config?.loginPath || "/api/auth/me", (resource, init) => fetch(resource, init).then(res => res.json()), {});

  return { user: !error ? user : null, error, isLoading, isValidating };
}

export type WithCentralAuthAutomaticLogin = <T extends { [key: string]: any }>(
  Component: ComponentType<T>,
  config?: Pick<BasePaths, "loginPath" | "profilePath">
) => FC<T>;


//Wrapper for a React based client to redirect an anonymous user to CentralAuth when visiting a page that requires authentication
export const withCentralAuthAutomaticLogin: WithCentralAuthAutomaticLogin = (Component, config = {}) => {
  return function withCentralAuthAutomaticLogin(props): ReactNode {
    const { loginPath, profilePath } = config;
    const [user, setUser] = useState<User>();

    useEffect(() => {
      fetch(profilePath || "/api/auth/me")
        .then(response => {
          response.json()
            .then((userData: User) => {
              if (userData == null)
                window.location.replace(loginPath || "/api/auth/login");
              else
                setUser(userData);
            })
        })

    }, [loginPath, profilePath]);

    if (user)
      return <Component {...props} />;

    return null;
  };
};