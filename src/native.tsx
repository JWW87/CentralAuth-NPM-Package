import { CryptoDigestAlgorithm, CryptoEncoding, digestStringAsync, randomUUID } from "expo-crypto";
import { deleteItemAsync, getItem, getItemAsync, setItemAsync } from 'expo-secure-store';
import * as WebBrowser from "expo-web-browser";
import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import { ValidationError } from "./server";
import { CentralAuthContextInterface, CentralAuthProviderProps, ErrorCode, ErrorObject, ReactNativeCallbackParams, TokenResponse } from "./types";

/**
 * This function takes a string input, applies SHA256 hashing, and converts the result
 * to base64url encoding by replacing URL-unsafe characters and removing padding.
 * 
 * @param string - The input string to be hashed
 * @returns A Promise that resolves to the base64url-encoded SHA256 hash of the input string
 * 
 * @example
 * ```typescript
 * const hashedValue = await hash("mySecretString");
 * console.log(hashedValue); // Returns base64url-encoded hash
 * ```
 */
export const hash = async (string: string): Promise<string> => {
  const base64Hash = await digestStringAsync(
    CryptoDigestAlgorithm.SHA256,
    string,
    { encoding: CryptoEncoding.BASE64 }
  );

  // Convert base64 to base64url
  return base64Hash
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

/**
 * Custom React hook for managing CentralAuth authentication in React Native applications.
 * 
 * This hook provides authentication functionality including login, callback handling, and logout
 * operations using OAuth 2.0 with PKCE (Proof Key for Code Exchange) flow.
 * 
 * @returns An object containing authentication methods and state:
 * - `login`: Initiates the OAuth login flow by generating PKCE parameters and opening the auth URL
 * - `handleCallback`: Processes the OAuth callback with authorization code and exchanges it for tokens
 * - `logout`: Clears stored access and ID tokens from both local state and secure storage
 * - `accessToken`: Current access token value
 * - `idToken`: Current ID token value
 * - `setAccessToken`: Function to set the access token
 * - `setIdToken`: Function to set the ID token
 * - `deleteAccessToken`: Function to delete the access token
 * - `deleteIdToken`: Function to delete the ID token
 * 
 * @throws {ValidationError} When authentication fails or invalid parameters are provided
 * 
 * @example
 * ```tsx
 * const { login, handleCallback, logout, accessToken } = useCentralAuth();
 * 
 * // Initiate login
 * await login();
 * 
 * // Handle callback from deep link
 * await handleCallback({ code: 'auth_code', errorCode: null, message: null });
 * 
 * // Logout user
 * await logout();
 * ```
 */
export const useCentralAuth = () => {
  //Get the auth context data
  const { clientId, authBaseUrl, callbackUrl, appId, deviceId, accessToken, idToken, setAccessToken, setIdToken, deleteAccessToken, deleteIdToken } = useContext(CentralAuthContext);

  // Handle login logic
  const login = useCallback(async () => {
    //Create a random state and store it in secure storage
    const state = randomUUID();
    await setItemAsync("state", state);
    //Create a code verifier and store it in secure storage
    const codeVerifier = randomUUID();
    await setItemAsync("code_verifier", codeVerifier);
    //Calculate the SHA256 hash as code challenge
    const codeChallenge = await hash(codeVerifier);

    //Build the URL to CentralAuth
    const loginURL = new URL(`${authBaseUrl}/login`);
    if (clientId)
      loginURL.searchParams.append("client_id", clientId);
    loginURL.searchParams.append("response_type", "code");
    loginURL.searchParams.append("redirect_uri", callbackUrl);
    loginURL.searchParams.append("state", state);
    loginURL.searchParams.append("code_challenge", codeChallenge);
    loginURL.searchParams.append("code_challenge_method", "S256");
    loginURL.searchParams.append("app_id", appId);
    loginURL.searchParams.append("device_id", deviceId || "");

    //Open the URL in a Web Browser tab
    await WebBrowser.openAuthSessionAsync(loginURL.toString(), callbackUrl);
  }, [clientId, authBaseUrl, callbackUrl, appId, deviceId]);

  //Handle the callback from CentralAuth
  const handleCallback = useCallback(async ({ code, errorCode, message }: ReactNativeCallbackParams) => {
    if (message || !code)
      throw new ValidationError({ errorCode: errorCode as ErrorCode, message });

    //Get the code verifier from secure storage
    const codeVerifier = await getItemAsync("code_verifier");
    const formData = new FormData();
    formData.append("code", code);
    formData.append("redirect_uri", callbackUrl);
    formData.append("code_verifier", codeVerifier || "");
    //Make a call to the verification endpoint
    const response = await fetch(`${authBaseUrl}/api/v1/verify`, {
      method: 'POST',
      body: formData
    });
    if (!response.ok) {
      const error = await response.json() as ErrorObject;
      throw new ValidationError(error);
    }
    const data = await response.json() as TokenResponse;

    //Set both tokens in the local state and secure storage
    await setAccessToken(data.access_token);
    await setIdToken(data.id_token);

    //Return the token response
    return data;
  }, [authBaseUrl, callbackUrl, setAccessToken, setIdToken]);

  const logout = useCallback(async () => {
    await deleteAccessToken();
    await deleteIdToken();
  }, [deleteAccessToken, deleteIdToken]);

  return { login, handleCallback, logout, accessToken, idToken, setAccessToken, setIdToken, deleteAccessToken, deleteIdToken };
}

//Context provider for React Native apps
export const CentralAuthContext = createContext<CentralAuthContextInterface>({
  clientId: null,
  appId: "",
  deviceId: null,
  authBaseUrl: "",
  callbackUrl: "",
  accessToken: undefined,
  idToken: undefined,
  setAccessToken: function (token: string): Promise<void> {
    throw new Error("Function not implemented.");
  },
  setIdToken: function (token: string): Promise<void> {
    throw new Error("Function not implemented.");
  },
  deleteAccessToken: function (): Promise<void> {
    throw new Error("Function not implemented.");
  },
  deleteIdToken: function (): Promise<void> {
    throw new Error("Function not implemented.");
  }
});

/**
 * CentralAuth Provider component that manages authentication state and token storage.
 * 
 * This component provides authentication context to its children, handling access tokens
 * and ID tokens with secure storage persistence. It automatically loads stored tokens
 * on initialization and provides methods to update and delete tokens.
 * 
 * @param props - The provider configuration props
 * @param props.clientId - The OAuth client identifier
 * @param props.appId - The application identifier
 * @param props.deviceId - The unique device identifier
 * @param props.callbackUrl - The URL to redirect to after authentication
 * @param props.authBaseUrl - The base URL for the authentication service
 * @param props.children - React children components that will have access to the auth context
 * 
 * @returns JSX element that provides authentication context to its children
 * 
 * @example
 * ```tsx
 * <CentralAuthProvider
 *   clientId="your-client-id"
 *   appId="your-app-id"
 *   deviceId="unique-device-id"
 *   callbackUrl="https://yourapp.com/callback"
 *   authBaseUrl="https://centralauth.com"
 * >
 *   <App />
 * </CentralAuthProvider>
 * ```
 */
export const CentralAuthProvider = ({ clientId, appId, deviceId, callbackUrl, authBaseUrl, children }: CentralAuthProviderProps) => {
  const [accessTokenState, setAccessTokenState] = useState<string | null>();
  const [idTokenState, setIdTokenState] = useState<string | null>();

  //Get the tokens from secure storage and set it in the state the first time the provider renders
  useEffect(() => {
    const accessTokenFromStorage = getItem("access_token");
    const idTokenFromStorage = getItem("id_token");
    setAccessTokenState(accessTokenFromStorage);
    setIdTokenState(idTokenFromStorage);
  }, []);

  const setAccessToken = useCallback(async (token: string) => {
    await setItemAsync("access_token", token);
    setAccessTokenState(token);
  }, []);

  const setIdToken = useCallback(async (token: string) => {
    await setItemAsync("id_token", token);
    setIdTokenState(token);
  }, []);

  const deleteAccessToken = useCallback(async () => {
    await deleteItemAsync("access_token");
    setAccessTokenState(null);
  }, []);

  const deleteIdToken = useCallback(async () => {
    await deleteItemAsync("id_token");
    setIdTokenState(null);
  }, []);

  return (
    <CentralAuthContext.Provider value={{ clientId, appId, deviceId, callbackUrl, authBaseUrl, accessToken: accessTokenState, idToken: idTokenState, setAccessToken, setIdToken, deleteAccessToken, deleteIdToken }}>
      {children}
    </CentralAuthContext.Provider>
  );
};