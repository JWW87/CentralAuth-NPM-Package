import type { ComponentType, FC, ReactElement, ReactNode } from "react";
import { BasePaths, ErrorObject } from "./types";
export type ReactNativeCallbackParams = {
    code?: string;
    state?: string;
} & Partial<ErrorObject>;
export type WithCentralAuthAutomaticLogin = <T extends {
    [key: string]: any;
}>(Component: ComponentType<T>, config?: Pick<BasePaths, "loginPath" | "profilePath"> & {
    PlaceholderComponent: ReactElement<any, any>;
}) => FC<T>;
export type CentralAuthProviderProps = {
    clientId: string | null;
    appId: string;
    deviceId?: string | null;
    authBaseUrl: string;
    callbackUrl: string;
    children: ReactNode;
};
