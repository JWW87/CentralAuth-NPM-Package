import { ComponentType, FC } from "react";
import { BasePaths, User } from ".";
export type WithCentralAuthAutomaticLogin = <T extends {
    [key: string]: any;
}>(Component: ComponentType<T>, config?: Pick<BasePaths, "loginPath" | "profilePath">) => FC<T>;
export declare const useUser: (config?: Pick<BasePaths, "profilePath">) => {
    user: User | null | undefined;
    error: any;
    isLoading: boolean;
    isValidating: boolean;
};
export declare const useUserRequired: (config?: Pick<BasePaths, "profilePath" | "loginPath">) => User | null;
export declare const withCentralAuthAutomaticLogin: WithCentralAuthAutomaticLogin;
