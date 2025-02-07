import { IncomingMessage, ServerResponse } from "http";
import { EncryptJWT, jwtDecrypt } from "jose";
import { CallbackParams, CallbackParamsHTTP, ConstructorParams, ErrorCode, ErrorObject, JWTPayload, LoginParams, LogoutParams, User, UserResponse } from "./types";

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
  private clientId: string | null;
  private secret: string;
  protected authBaseUrl: string;
  protected callbackUrl: string;
  private token?: string;
  protected user?: User;

  //Constructor method to set all instance variable
  constructor({ clientId, secret, authBaseUrl, callbackUrl }: ConstructorParams) {
    this.clientId = clientId;
    this.secret = secret;
    this.authBaseUrl = authBaseUrl;
    this.callbackUrl = callbackUrl;
  }

  //Private method to check whether all variable are set for a specific action
  //Will throw a ValidationError when a check fails
  private checkData = (action: "login" | "callback" | "verify" | "me") => {
    let error: ErrorObject | null = null;
    if (typeof this.clientId === "undefined")
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
      const textEncoder = new TextEncoder();
      const { payload: decodedToken } = await jwtDecrypt<JWTPayload>(this.token!, textEncoder.encode(this.secret));

      return decodedToken;
    } catch (error: any) {
      throw new ValidationError({ errorCode: error?.name, message: error?.message });
    }
  }

  //Private method to set the payload of the JWT
  private setToken = async (payload: JWTPayload) => {
    const textEncoder = new TextEncoder();
    this.token = await new EncryptJWT(payload)
      .setProtectedHeader({ alg: "dir", enc: "A256CBC-HS512" })
      .setIssuedAt()
      .encrypt(textEncoder.encode(this.secret));
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
    const ip = forwardedFor || realIp || null;
    //The IP address might consist of multiple IP addresses, seperated by commas. Only return the first IP address
    return ip ? ip.split(",")[0] : "0.0.0.0";
  }

  //Private method to get the user data from cache or the CentralAuth server
  //Will throw an error when the request fails
  private getUser = async (jwtPayload: JWTPayload, userAgent: string, ipAddress: string) => {
    if (this.user)
      return this.user;
    else {
      this.checkData("me");

      const { user, session } = jwtPayload

      if (user && session) {

      } else {
        //Get the user and session data from the CentralAuth server
        const headers = new Headers();
        headers.set("Authorization", `Bearer ${this.token!}`);
        //Set the user agent to the user agent of the current request
        headers.set("user-agent", userAgent);
        //Set the custom auth-ip header with the IP address of the current request
        headers.set("auth-ip", ipAddress);

        //Construct the URL
        const requestUrl = new URL(`${this.authBaseUrl}/api/v1/me/${jwtPayload.sessionId}`);
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
  }

  //Private method to populate the token argument from the cookie in the session
  private setTokenFromCookie = async (headers: Headers) => {
    const cookies = parseCookie(headers.get("cookie"));
    //Check for a sessionToken in the cookies
    if (cookies["sessionToken"])
      this.token = cookies["sessionToken"];
  }

  //Public method to get the user data from the current request headers
  //The JWT will be set based on the sessionToken cookie in the request header
  //Will throw an error when the request fails or the token could not be decoded
  public getUserData = async (headers: Headers) => {
    //Populate the token
    await this.setTokenFromCookie(headers);
    //Decode the token to get the session ID
    const jwtPayload = await this.getDecodedToken();

    //Get the user data from cache or CentralAuth
    await this.getUser(jwtPayload, this.getUserAgent(headers), this.getIPAddress(headers));

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
    const textEncoder = new TextEncoder();
    const translations = config?.translations ? textEncoder.encode(JSON.stringify(config.translations)) : null;

    //Redirect to the login page
    const loginUrl = new URL(`${this.authBaseUrl}/login/${this.clientId || ""}`);
    //Add an error message when given
    if (config?.errorMessage)
      loginUrl.searchParams.set("errorMessage", config?.errorMessage);
    //Add a default email address when given
    if (config?.emailAddress)
      loginUrl.searchParams.set("emailAddress", config?.emailAddress);
    //Add translations when given
    if (translations)
      loginUrl.searchParams.set("translations", Buffer.from(translations).toString("base64"));
    //Add embed boolean when given
    if (config?.embed)
      loginUrl.searchParams.set("embed", "1");
    loginUrl.searchParams.set("callbackUrl", callbackUrl.toString());

    return Response.redirect(loginUrl.toString());
  }

  //Public method for the callback procedure when returning from CentralAuth
  public callback = async (req: Request, config?: CallbackParams) => {
    const res = await this.processCallback(req);

    //When an onAfterCallback function is given, call it with the user data
    //The onAfterCallback function may return a new/altered response, which will be returned instead of the default response object
    let callbackResponse: Response | void | null = null;
    if (config?.onAfterCallback)
      callbackResponse = await config.onAfterCallback(req, res, this.user!);

    //Set a cookie with the JWT and redirect to the returnTo URL
    return callbackResponse || res;
  }

  //Protected method for processing the callback
  //This method will automatically verify the JWT payload and set the sessionToken cookie
  //Optionally calls a custom callback function when given with the user data as an argument
  //Returns a Response with a redirection to the returnTo URL
  //Will throw an error when the verification procedure fails or the user data could not be fetched
  protected processCallback = async (req: Request) => {
    const url = new URL(req.url);
    const searchParams = url.searchParams;
    const returnTo = searchParams.get("returnTo") || url.origin;
    const sessionId = searchParams.get("sessionId");
    const verificationState = searchParams.get("verificationState");
    const errorCode = searchParams.get("errorCode");
    const errorMessage = searchParams.get("errorMessage");

    if (!sessionId || !verificationState)
      throw new ValidationError({ errorCode: "missingFields", message: "The session ID and/or verification state are missing in the callback URL." });

    if (errorCode) {
      //When the error code is set, something went wrong in the login procedure
      //Throw a ValidationError
      throw new ValidationError({ errorCode: errorCode as ErrorCode, message: errorMessage || "" })
    }

    //Build the JWT with the session ID and verification state as payload
    await this.setToken({ sessionId, verificationState });
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
    const response = await verifyResponse.json() as UserResponse;
    this.user = response.user;

    //Add the user and session data to the token
    await this.setToken({
      sessionId,
      verificationState,
      ...response
    });

    //Set the default response object
    let res = new Response(null,
      {
        status: 302,
        headers: {
          "Location": returnTo,
          "Set-Cookie": `sessionToken=${this.token}; Path=/; HttpOnly; Max-Age=100000000; SameSite=Lax; Secure`
        }
      }
    );

    //Set a cookie with the JWT and redirect to the returnTo URL
    return res;
  }

  //Public method to get the user data from the current request
  //This method wraps getUserData and returns a Response with the user data as JSON in the body
  //Will return a NULL response on error
  public me = async (req: Request) => {
    try {
      const headers = req.headers;
      const jwtPayload = await this.getDecodedToken();
      await this.getUserData(headers);
      //Update the payload in the session token cookie
      await this.setToken({
        ...jwtPayload,
        user: this.user,
        session: {
          ...jwtPayload.session!,
          lastSync: new Date().toISOString()
        }
      });
      //Return the user and update the session token cookie
      return Response.json(this.user, {
        headers: {
          "Set-Cookie": `sessionToken=${this.token}; Path=/; HttpOnly; Max-Age=100000000; SameSite=Lax; Secure`
        }
      });
    } catch (error) {
      //When an error occurs, assume the user session is not valid anymore
      //Delete the cookie
      return Response.json(null, {
        headers: {
          "Set-Cookie": "sessionToken= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure"
        }
      })
    }
  }

  //Public method to logout
  public logout = async (req: Request, config?: LogoutParams) => {
    const returnTo = this.getReturnToURL(req, config);
    const headerList = req.headers;

    try {
      if (config?.LogoutSessionWide) {
        //To log out session wide, invalidate the session at CentralAuth
        await this.setTokenFromCookie(headerList);
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
            "Set-Cookie": "sessionToken= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure"
          }
        }
      );
    }
  }
}

//Define a subclass for HTTP based servers
export class CentralAuthHTTPClass extends CentralAuthClass {
  //Private method for converting a HTTP Request to a Fetch API Request
  private httpRequestToFetchRequest = (httpRequest: IncomingMessage) => {
    const baseUrl = new URL(this.callbackUrl);

    const fetchRequest = new Request(new URL(httpRequest.url!, baseUrl.origin), {
      headers: new Headers({ ...httpRequest.headers as HeadersInit })
    });

    return fetchRequest;
  }

  //Private method for converting a Fetch API response to an HTTP Response
  private fetchResponseToHttpResponse = async (fetchResponse: Response, httpResponse: ServerResponse) => {
    const entries = fetchResponse.headers.entries();
    const httpHeaders: Record<string, string> = {};
    for (const entry of entries)
      httpHeaders[entry[0]] = entry[1];

    const body = await fetchResponse.text();
    httpResponse.writeHead(fetchResponse.status, httpHeaders).end(body);
  }

  //Overloaded method for getUserData
  public getUserDataHTTP = async (req: IncomingMessage) => {
    const request = this.httpRequestToFetchRequest(req);
    return await this.getUserData(request.headers);
  }

  //Overloaded method for login
  public loginHTTP = async (req: IncomingMessage, res: ServerResponse, config?: LoginParams) => {
    const fetchResponse = await this.login(this.httpRequestToFetchRequest(req), config);

    await this.fetchResponseToHttpResponse(fetchResponse, res);
  }

  //Overloaded method for callback
  public callbackHTTP = async (req: IncomingMessage, res: ServerResponse, config?: CallbackParamsHTTP) => {
    const fetchResponse = await this.processCallback(this.httpRequestToFetchRequest(req));

    //When an onAfterCallback function is given, call it with the user data
    //The onAfterCallback function may return a new/altered response, which will be returned instead of the default response object
    let callbackResponse: Response | void | null = null;
    if (config?.onAfterCallback)
      callbackResponse = await config.onAfterCallback(req, res, fetchResponse, this.user!);

    await this.fetchResponseToHttpResponse(callbackResponse || fetchResponse, res);
  }

  //Overloaded method for logout
  public logoutHTTP = async (req: IncomingMessage, res: ServerResponse, config?: LogoutParams) => {
    const fetchResponse = await this.logout(this.httpRequestToFetchRequest(req), config);

    await this.fetchResponseToHttpResponse(fetchResponse, res);
  }

  //Overloaded method for me
  public meHTTP = async (req: IncomingMessage, res: ServerResponse) => {
    const fetchResponse = await this.me(this.httpRequestToFetchRequest(req));

    await this.fetchResponseToHttpResponse(fetchResponse, res);
  }
}