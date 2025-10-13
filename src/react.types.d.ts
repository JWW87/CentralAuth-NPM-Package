import type { ComponentType, FC, ReactElement } from "react";
import { BasePaths } from "./types";
export type WithCentralAuthAutomaticLogin = <T extends {
    [key: string]: any;
}>(Component: ComponentType<T>, config?: Pick<BasePaths, "loginPath" | "profilePath"> & {
    PlaceholderComponent: ReactElement<any, any>;
}) => FC<T>;
