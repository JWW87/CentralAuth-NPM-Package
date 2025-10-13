import type { WithCentralAuthAutomaticLogin } from "./react.types";
import type { BasePaths, User } from "./types";
export declare const useUser: (config?: Pick<BasePaths, "profilePath">) => {
    user: User | null | undefined;
    error: any;
    isLoading: boolean;
    isValidating: boolean;
};
export declare const useUserRequired: (config?: Pick<BasePaths, "profilePath" | "loginPath">) => User | null;
export declare const withCentralAuthAutomaticLogin: WithCentralAuthAutomaticLogin;
