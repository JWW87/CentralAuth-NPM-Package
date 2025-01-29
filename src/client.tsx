"use client"

import { ReactElement, createElement, useEffect, useState } from "react";
import useSWR from "swr";
import type { BasePaths, User, WithCentralAuthAutomaticLogin } from "./types";

//React hook to declaratively get the currently logged in user via SWR. See https://swr.vercel.app for more info on SWR.
//Param basePath can be used when the API route for /me is different from the default /api/auth/me
//Will return null when the user is not logged in or on error, and undefined when the request is still active
//The error object will be populated with the fetcher error when the request failed
export const useUser = (config?: Pick<BasePaths, "profilePath">) => {
  const { data: user, error, isLoading, isValidating } = useSWR<User | null>(config?.profilePath || "/api/auth/me", (resource, init) => fetch(resource, init).then(res => res.json()), {});

  return { user: !error ? user : null, error, isLoading, isValidating };
}
//React hook to declaratively get the currently logged in user.
//When the user could not be fetched, redirect the user to the login page
//Returns the user object when the user is logged in, and null when the user is being fetched
export const useUserRequired = (config?: Pick<BasePaths, "profilePath" | "loginPath">) => {
  const { user, isLoading } = useUser(config);

  useEffect(() => {
    if (!user && !isLoading) {
      //User is not logged in, redirect to the login page
      window.location.replace(config?.loginPath || "/api/auth/login");
    }
  }, [user, isLoading]);

  return user || null;
}
//Wrapper for a React based client to redirect an anonymous user to CentralAuth when visiting a page that requires authentication
export const withCentralAuthAutomaticLogin: WithCentralAuthAutomaticLogin = (Component, config) => {
  return function WithCentralAuthAutomaticLogin(props): ReactElement<any, any> | null {
    const PlaceholderComponent = config?.PlaceholderComponent || null;
    const [user, setUser] = useState<User>();

    useEffect(() => {
      fetch(config?.profilePath || "/api/auth/me")
        .then(response => {
          response.json()
            .then((userData: User) => {
              if (userData == null)
                window.location.replace(config?.loginPath || "/api/auth/login");
              else
                setUser(userData);
            })
        })

    }, [config]);

    if (user)
      return createElement(Component, Object.assign({}, props));

    return PlaceholderComponent;
  };
};