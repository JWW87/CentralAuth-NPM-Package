import React, { ComponentType, FC, ReactElement, useEffect, useState } from "react";
import useSWR from "swr";
import { BasePaths, User } from ".";

export type WithCentralAuthAutomaticLogin = <T extends { [key: string]: any }>(
  Component: ComponentType<T>,
  config?: Pick<BasePaths, "loginPath" | "profilePath">
) => FC<T>;

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
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    if (!user) {
      //Fetch the user
      fetch(config?.profilePath || "/api/auth/me")
        .then(async response => {
          if (response.ok) {
            //User was found, populate the state variable with the user object
            const user = await response.json() as User;
            setUser(user);
          } else {
            //User is not logged in, redirect to the login page
            window.location.replace(config?.loginPath || "/api/auth/login")
          }
        })
    }
  }, [user]);

  return user;
}


//Wrapper for a React based client to redirect an anonymous user to CentralAuth when visiting a page that requires authentication
export const withCentralAuthAutomaticLogin: WithCentralAuthAutomaticLogin = (Component, config = {}) => {
  return function withCentralAuthAutomaticLogin(props): ReactElement<any, any> | null {
    const { loginPath, profilePath } = config;
    const [user, setUser] = useState<User>();

    useEffect(() => {
      fetch(profilePath || "/api/auth/me")
        .then(response => {
          response.json()
            .then((userData: User) => {
              if (userData == null)
                window.location.replace(loginPath || "/api/auth/login");
              else
                setUser(userData);
            })
        })

    }, [loginPath, profilePath]);

    if (user)
      return <Component {...props} />;

    return null;
  };
};