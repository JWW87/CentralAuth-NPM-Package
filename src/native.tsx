import { CryptoDigestAlgorithm, CryptoEncoding, digestStringAsync, randomUUID } from "expo-crypto";
import { openURL } from "expo-linking";
import { deleteItemAsync, getItem, getItemAsync, setItemAsync } from 'expo-secure-store';
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
 * Custom React hook for handling CentralAuth authentication in React Native applications.
 * 
 * This hook provides a complete authentication flow including login, logout, token management,
 * and callback handling for OAuth 2.0 with PKCE (Proof Key for Code Exchange).
 * 
 * @returns An object containing authentication methods and token states
 * @returns {Function} login - Initiates the OAuth login flow by opening the authorization URL
 * @returns {Function} handleCallback - Processes the OAuth callback and exchanges code for tokens
 * @returns {Function} logout - Clears all stored tokens and logs out the user
 * @returns {Function} setAccessToken - Manually sets the access token in storage and state
 * @returns {Function} setIdToken - Manually sets the ID token in storage and state
 * @returns {Function} deleteAccessToken - Removes the access token from storage and state
 * @returns {Function} deleteIdToken - Removes the ID token from storage and state
 * @returns {string | null} accessToken - Current access token from state
 * @returns {string | null} idToken - Current ID token from state
 * 
 * @throws {ValidationError} When callback contains an error or verification fails
 */
export const useCentralAuth = () => {
  const [accessTokenState, setAccessTokenState] = useState<string | null>();
  const [idTokenState, setIdTokenState] = useState<string | null>();

  //Get the auth context data
  const centralAuthContextData = useContext(CentralAuthContext);

  //Get the tokens from secure storage and set it in the state the first time this hook is used
  useEffect(() => {
    const accessTokenFromStorage = getItem("access_token");
    const idTokenFromStorage = getItem("id_token");
    setAccessTokenState(accessTokenFromStorage);
    setIdTokenState(idTokenFromStorage);
  }, []);

  const login = useCallback(async () => {
    // Handle login logic
    const { clientId, authBaseUrl, callbackUrl, appId, deviceId } = centralAuthContextData;

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

    //Open the URL
    openURL(loginURL.toString());
  }, [centralAuthContextData]);

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

  const handleCallback = useCallback(async ({ code, errorCode, message }: ReactNativeCallbackParams) => {
    //Handle the callback from CentralAuth
    if (message || !code)
      throw new ValidationError({ errorCode: errorCode as ErrorCode, message });

    //Verify the code in the callback URL
    const { authBaseUrl, callbackUrl } = centralAuthContextData;

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
  }, [centralAuthContextData, setAccessToken, setIdToken]);

  const logout = useCallback(async () => {
    await deleteAccessToken();
    await deleteIdToken();
  }, [deleteAccessToken, deleteIdToken]);

  return { login, handleCallback, logout, setAccessToken, setIdToken, deleteAccessToken, deleteIdToken, accessToken: accessTokenState, idToken: idTokenState };
}

//Context provider for React Native apps
export const CentralAuthContext = createContext<CentralAuthContextInterface>({
  clientId: null,
  appId: "",
  deviceId: null,
  authBaseUrl: "",
  callbackUrl: "",
});

export const CentralAuthProvider = ({ clientId, appId, deviceId, callbackUrl, authBaseUrl, children }: CentralAuthProviderProps) => {
  return (
    <CentralAuthContext.Provider value={{ clientId, appId, deviceId, callbackUrl, authBaseUrl }}>
      {children}
    </CentralAuthContext.Provider>
  );
};