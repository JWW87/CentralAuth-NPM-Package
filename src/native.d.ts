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
export declare const useCentralAuth: () => {
    login: () => Promise<void>;
    handleCallback: ({ code, errorCode, message }: ReactNativeCallbackParams) => Promise<TokenResponse>;
    logout: () => Promise<void>;
    accessToken: string | null | undefined;
    idToken: string | null | undefined;
    setAccessToken: (token: string) => Promise<void>;
    setIdToken: (token: string) => Promise<void>;
    deleteAccessToken: () => Promise<void>;
    deleteIdToken: () => Promise<void>;
};
export declare const CentralAuthContext: React.Context<CentralAuthContextInterface>;
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
export declare const CentralAuthProvider: ({ clientId, appId, deviceId, callbackUrl, authBaseUrl, children }: CentralAuthProviderProps) => React.JSX.Element;
