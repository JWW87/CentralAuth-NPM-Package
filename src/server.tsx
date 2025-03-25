import { randomUUID } from "crypto";
import { IncomingMessage, ServerResponse } from "http";
import { EncryptJWT, jwtDecrypt } from "jose";
import { AuthorizationCode } from 'simple-oauth2';
import { CallbackParams, CallbackParamsHTTP, ConstructorParams, ErrorCode, ErrorObject, ExperimentalCacheOptions, JWTPayload, LoginParams, LogoutParams, User } from "./types";

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
  private cache?: ExperimentalCacheOptions;
  private debug?: boolean;
  private token?: string;
  protected userData?: User;

  //Constructor method to set all instance variable
  constructor({ clientId, secret, authBaseUrl, callbackUrl, cache, debug }: ConstructorParams) {
    if (debug)
      console.log(`[CENTRALAUTH DEBUG] CentralAuth class instantiated for client ${clientId || "CentralAuth"}.`);
    this.clientId = clientId;
    this.secret = secret;
    this.authBaseUrl = authBaseUrl;
    this.callbackUrl = callbackUrl;
    this.cache = cache;
    this.debug = debug;
  }

  //Private method to get the Simple OAuth client
  private getOAuthClient = () => {
    return new AuthorizationCode({
      client: {
        id: this.clientId || "",
        secret: this.secret,
      },
      auth: {
        tokenHost: this.authBaseUrl,
        tokenPath: '/api/v1/verify',
        authorizePath: '/login',
      }
    })
  }

  //Private method to check whether all variable are set for a specific action
  //Will throw a ValidationError when a check fails
  private checkData = (action: "login" | "callback" | "verify" | "user") => {
    let error: ErrorObject | null = null;
    if (typeof this.clientId === "undefined")
      error = { errorCode: "organizationIdMissing", message: "The organization ID is missing. This ID can be found on the organization page in your admin console." };
    if (!this.secret)
      error = { errorCode: "secretMissing", message: "The secret is missing. The secret is shown only once at the creation of an organization and should never be exposed publicly or stored unsafely." };
    if (!this.callbackUrl)
      error = { errorCode: "callbackUrlMissing", message: "The callback URL is missing." };
    if (!this.authBaseUrl)
      error = { errorCode: "authBaseUrlMissing", message: "The base URL for the organization is missing. The base URL is either the internal base URL or a custom domain for your organization." };
    if ((action == "callback" || action == "verify") && !this.token)
      error = { errorCode: "tokenMissing", message: "The JSON Web Token is missing. A JWT must be created in the callback after a successful login attempt." };
    if (action == "user" && !this.token)
      error = { errorCode: "tokenMissing", message: "The JSON Web Token is missing. This means the user is not logged in or the token is invalid." };

    if (error) {
      if (this.debug)
        console.error(`[CENTRALAUTH DEBUG] Data check failed for client ${this.clientId || "CentralAuth"} in ${action}: ${error.message}`);
      throw new ValidationError(error);
    }
  }

  //Private method to populate the token, either from the cookie of the token bearer in the headers
  private populateToken = async (headers: Headers) => {//Populate the token from token bearer or cookie
    const authHeader = headers.get("Authorization");
    if (authHeader)
      await this.setTokenFromTokenBearer(headers);
    else
      await this.setTokenFromCookie(headers);
  }

  //Private method to get the decoded token
  //Can only be used after the token has been set in this object
  private getDecodedToken = async () => {
    this.checkData("callback");

    try {
      //Decode the JWT
      const textEncoder = new TextEncoder();
      const { payload: decodedToken } = await jwtDecrypt<JWTPayload>(this.token!, textEncoder.encode(this.secret));

      return decodedToken;
    } catch (error: any) {
      if (this.debug)
        console.error(`[CENTRALAUTH DEBUG] Failed to decode token for client ${this.clientId || "CentralAuth"}: ${error.message}`);
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
    const returnToParam = url.searchParams.get("return_to");
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
      if (referrer && !referrer.startsWith("about") && referrer != this.authBaseUrl)
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
  //Will update the contents of the token with user and session data
  private getUser = async (headers: Headers) => {
    if (this.userData)
      return this.userData;
    else {
      //Get the decoded token
      const jwtPayload = await this.getDecodedToken();
      const { user, session } = jwtPayload;

      this.checkData("user");

      //Get the IP address and user agent from the headers
      const ipAddress = this.getIPAddress(headers);
      const userAgent = this.getUserAgent(headers);

      //Check if user data should be fetched from cache
      const cached = user && session && !!session?.lastSync && this.cache?.enabled && this.cache.cacheLifeTime ? new Date().getTime() - new Date(session.lastSync).getTime() < this.cache.cacheLifeTime * 1000 : false;

      if (user && session && cached) {
        if (this.debug)
          console.log(`[CENTRALAUTH DEBUG] User data fetched from cache for client ${this.clientId || "CentralAuth"}.`);
        //Check if hijack protection is disabled or the IP address and user agent of the current user matches the IP address and user agent of the session
        if (this.cache?.cacheHijackProtection === false || (session.ipAddress === ipAddress && session.userAgent === userAgent))
          this.userData = user;
        else {
          if (this.debug)
            console.error(`[CENTRALAUTH DEBUG] Cached data could not be fetched for client ${this.clientId || "CentralAuth"}.`);
          this.userData = undefined;
          throw new ValidationError({ errorCode: "sessionInvalid", message: "The session is invalid. The IP address and/or user agent of the current request do not match the IP address and/or user agent of the session." });
        }
      } else {
        //Get the user and session data from the CentralAuth server
        const headers = new Headers();
        headers.set("Content-Type", "text/plain");
        headers.set("Authorization", `Basic ${Buffer.from(`${this.clientId || ""}:${this.secret}`).toString("base64")}`);
        //Set the user agent to the user agent of the current request
        headers.set("user-agent", userAgent);
        //Set the custom auth-ip header with the IP address of the current request
        headers.set("auth-ip", ipAddress);

        //Construct the URL
        const requestUrl = new URL(`${this.authBaseUrl}/api/v1/userinfo`);
        const callbackUrl = new URL(this.callbackUrl!);
        requestUrl.searchParams.set("domain", callbackUrl.origin);

        const response = await fetch(requestUrl.toString(),
          {
            method: "POST",
            body: this.token,
            headers
          });
        if (!response.ok) {
          const error = await response.json() as ErrorObject;
          if (this.debug)
            console.error(`[CENTRALAUTH DEBUG] Failed to fetch user data from the server for client ${this.clientId || "CentralAuth"}: ${error.message}`);
          throw new ValidationError(error);
        }

        this.userData = await response.json() as User;

        if (this.userData && session) {
          //Update the payload in the session token cookie
          await this.setToken({
            ...jwtPayload,
            user: this.userData,
            session: {
              ...session,
              lastSync: cached ? session.lastSync : new Date().toISOString()
            }
          });
        }
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

  //Private method to populate the token argument from the JWT in the token bearer header
  private setTokenFromTokenBearer = async (headers: Headers) => {
    const authHeader = headers.get("Authorization");
    //Check for a token bearer header
    if (authHeader && authHeader.startsWith("Bearer "))
      this.token = authHeader.substring(7);
  }

  //Public method to get the user data from the current request headers
  //The JWT will be set based on the sessionToken cookie or token bearer in the request header
  //Will throw an error when the request fails or the token could not be decoded
  public getUserData = async (headers: Headers) => {
    //Get the user data from cache or CentralAuth
    await this.populateToken(headers);
    await this.getUser(headers);

    return this.userData || null;
  }

  //Public method to start the login procedure
  //Will throw an error when the procedure could not be started
  public login = async (req: Request, config?: LoginParams) => {
    this.checkData("login");

    const returnTo = this.getReturnToURL(req, config);
    const callbackUrl = new URL(this.callbackUrl);
    if (returnTo)
      callbackUrl.searchParams.set("return_to", returnTo);

    //Get a new OAuth client
    const client = this.getOAuthClient();
    //Construct the base URL for the OAuth login
    const authorizationUriParams: { [key: string]: string } = {
      redirect_uri: callbackUrl.toString()
    };

    //Add an error message when given
    if (config?.errorMessage)
      authorizationUriParams.error_message = config.errorMessage;
    //Add a default email address when given
    if (config?.email)
      authorizationUriParams.email = config.email;
    //Add OAuth state when given, otherwise fall back to a random state
    authorizationUriParams.state = config?.state || randomUUID();
    //Add translations when given
    if (config?.translations)
      authorizationUriParams.translations = Buffer.from(JSON.stringify(config.translations)).toString("base64");
    //Add embed boolean when given
    if (config?.embed)
      authorizationUriParams.embed = "1";

    const authorizationUri = new URL(client.authorizeURL(authorizationUriParams));

    if (this.debug)
      console.log(`[CENTRALAUTH DEBUG] Starting login procedure for client ${this.clientId || "CentralAuth"}, redirecting to ${authorizationUri.toString()}.`);

    //Redirect to the authorization URI
    return Response.redirect(authorizationUri.toString());
  }

  //Public method for the callback procedure when returning from CentralAuth
  public callback = async (req: Request, config?: CallbackParams) => {
    const res = await this.processCallback(req, config?.onStateReceived);

    //When an onAfterCallback function is given, call it with the user data
    //The onAfterCallback function may return a new/altered response, which will be returned instead of the default response object
    let callbackResponse: Response | void | null = null;
    if (config?.onAfterCallback)
      callbackResponse = await config.onAfterCallback(req, res, this.userData!);

    //Set a cookie with the JWT and redirect to the returnTo URL
    return callbackResponse || res;
  }

  //Protected method for processing the callback
  //This method will process the OAuth code and verify the user session with it
  //The user object will be retrieved based on the returned access JWT
  //Optionally calls a custom callback function when given with the user object as an argument
  //Returns a Response with a redirection to the returnTo URL
  //Will throw an error when the verification procedure fails or the user object could not be fetched
  protected processCallback = async (req: Request, onStateReceived?: CallbackParams["onStateReceived"]) => {
    const url = new URL(req.url);
    const searchParams = url.searchParams;
    const returnTo = searchParams.get("return_to") || url.origin;
    const code = searchParams.get("code");
    const state = searchParams.get("state");
    const errorCode = searchParams.get("error_code");
    const errorMessage = searchParams.get("error_message");

    //If the state is given and an onStateReceived function is given, call it to verify the state
    if (state && onStateReceived) {
      const stateVerification = await onStateReceived(req, state);
      if (!stateVerification) {
        if (this.debug)
          console.error(`[CENTRALAUTH DEBUG] State verification failed for client ${this.clientId || "CentralAuth"}`);
        throw new ValidationError({ errorCode: "stateInvalid", message: "State verification failed." });
      }
    }

    if (errorCode) {
      //When the error code is set, something went wrong in the login procedure
      //Throw a ValidationError
      if (this.debug)
        console.error(`[CENTRALAUTH DEBUG] Error in login procedure for client ${this.clientId || "CentralAuth"}: ${errorMessage}`);
      throw new ValidationError({ errorCode: errorCode as ErrorCode, message: errorMessage || "" });
    }

    if (!code) {
      if (this.debug)
        console.error(`[CENTRALAUTH DEBUG] Callback could not be processed for client ${this.clientId || "CentralAuth"}, missing code.`);
      throw new ValidationError({ errorCode: "missingFields", message: "The code is missing in the callback URL." });
    }

    const [sessionId, verificationState] = code.split("|");
    if (!sessionId || !verificationState) {
      if (this.debug)
        console.error(`[CENTRALAUTH DEBUG] Callback could not be processed for client ${this.clientId || "CentralAuth"}, missing session ID and/or verification state.`);
      throw new ValidationError({ errorCode: "missingFields", message: "The session ID and/or verification state are missing in the callback URL." });
    }

    //Get a new OAuth client
    const client = this.getOAuthClient();
    //Get an access JWT based on the given code
    const tokenObject = await client.getToken({
      redirect_uri: this.callbackUrl,
      code
    });
    //Set the token in this object
    this.token = tokenObject.token.token as string;

    //Get the user data from the CentralAuth server
    await this.getUser(req.headers);

    //Add the user and session data to the token
    await this.setToken({
      sessionId,
      user: this.userData,
      session: {
        ipAddress: this.getIPAddress(req.headers),
        userAgent: this.getUserAgent(req.headers),
        lastSync: new Date().toISOString()
      }
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
  public user = async (req: Request) => {
    try {
      const headers = req.headers;

      await this.getUserData(headers);

      //Return the user and update the session token cookie
      return Response.json(this.userData, {
        headers: {
          "Set-Cookie": `sessionToken=${this.token}; Path=/; HttpOnly; Max-Age=100000000; SameSite=Lax; Secure`
        }
      });
    } catch (error: any) {
      //When an error occurs, assume the user session is not valid anymore
      //Delete the cookie
      if (this.debug)
        console.error(`[CENTRALAUTH DEBUG] Error fetching user data from cache or CentralAuth server or validation error for client ${this.clientId || "CentralAuth"}: ${error?.message}`);
      return Response.json(null, {
        headers: {
          "Set-Cookie": "sessionToken= ; Path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax; Secure"
        }
      });
    }
  }

  //Public method to logout
  public logout = async (req: Request, config?: LogoutParams) => {
    const returnTo = this.getReturnToURL(req, config);
    const headerList = req.headers;

    try {
      if (config?.LogoutSessionWide) {
        //Populate the token in this object
        await this.populateToken(headerList);
        //To log out session wide, invalidate the session at CentralAuth
        const headers = new Headers();
        headers.set("Content-Type", "text/plain");
        headers.set("Authorization", `Basic ${Buffer.from(`${this.clientId || ""}:${this.secret}`).toString("base64")}`);

        const logoutResponse = await fetch(`${this.authBaseUrl}/api/v1/logout`,
          {
            method: "POST",
            body: this.token,
            headers
          });
        if (!logoutResponse.ok) {
          const error = await logoutResponse.json() as ErrorObject;
          throw new ValidationError(error);
        }
      }
    } catch (error: any) {
      if (this.debug)
        console.error(`[CENTRALAUTH DEBUG] Error logging out session-wide for client ${this.clientId || "CentralAuth"}: ${error?.message}`);
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
    const fetchResponse = await this.processCallback(this.httpRequestToFetchRequest(req), config?.onStateReceived);

    //When an onAfterCallback function is given, call it with the user data
    //The onAfterCallback function may return a new/altered response, which will be returned instead of the default response object
    let callbackResponse: Response | void | null = null;
    if (config?.onAfterCallback)
      callbackResponse = await config.onAfterCallback(req, res, fetchResponse, this.userData!);

    await this.fetchResponseToHttpResponse(callbackResponse || fetchResponse, res);
  }

  //Overloaded method for logout
  public logoutHTTP = async (req: IncomingMessage, res: ServerResponse, config?: LogoutParams) => {
    const fetchResponse = await this.logout(this.httpRequestToFetchRequest(req), config);

    await this.fetchResponseToHttpResponse(fetchResponse, res);
  }

  //Overloaded method for user
  public userHTTP = async (req: IncomingMessage, res: ServerResponse) => {
    const fetchResponse = await this.user(this.httpRequestToFetchRequest(req));

    await this.fetchResponseToHttpResponse(fetchResponse, res);
  }
}