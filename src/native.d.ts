import React from "react";
import { CentralAuthContextInterface, CentralAuthProviderProps, ReactNativeCallbackParams, TokenResponse } from "./types";
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
export declare const hash: (string: string) => Promise<string>;
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
export declare const useCentralAuth: () => {
    login: () => Promise<void>;
    handleCallback: ({ code, errorCode, message }: ReactNativeCallbackParams) => Promise<TokenResponse>;
    logout: () => Promise<void>;
    setAccessToken: (token: string) => Promise<void>;
    setIdToken: (token: string) => Promise<void>;
    deleteAccessToken: () => Promise<void>;
    deleteIdToken: () => Promise<void>;
    accessToken: string | null | undefined;
    idToken: string | null | undefined;
};
export declare const CentralAuthContext: React.Context<CentralAuthContextInterface>;
export declare const CentralAuthProvider: ({ clientId, appId, deviceId, callbackUrl, authBaseUrl, children }: CentralAuthProviderProps) => React.JSX.Element;
