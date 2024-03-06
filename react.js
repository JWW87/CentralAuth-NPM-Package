var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import React, { useEffect, useState } from "react";
import useSWR from "swr";
//React hook to declaratively get the currently logged in user via SWR. See https://swr.vercel.app for more info on SWR.
//Param basePath can be used when the API route for /me is different from the default /api/auth/me
//Will return null when the user is not logged in or on error, and undefined when the request is still active
//The error object will be populated with the fetcher error when the request failed
export const useUser = (config) => {
    const { data: user, error, isLoading, isValidating } = useSWR((config === null || config === void 0 ? void 0 : config.profilePath) || "/api/auth/me", (resource, init) => fetch(resource, init).then(res => res.json()), {});
    return { user: !error ? user : null, error, isLoading, isValidating };
};
//React hook to declaratively get the currently logged in user.
//When the user could not be fetched, redirect the user to the login page
//Returns the user object when the user is logged in, and null when the user is being fetched
export const useUserRequired = (config) => {
    const [user, setUser] = useState(null);
    useEffect(() => {
        if (!user) {
            //Fetch the user
            fetch((config === null || config === void 0 ? void 0 : config.profilePath) || "/api/auth/me")
                .then((response) => __awaiter(void 0, void 0, void 0, function* () {
                if (response.ok) {
                    //User was found, populate the state variable with the user object
                    const user = yield response.json();
                    setUser(user);
                }
                else {
                    //User is not logged in, redirect to the login page
                    window.location.replace((config === null || config === void 0 ? void 0 : config.loginPath) || "/api/auth/login");
                }
            }));
        }
    }, [user]);
    return user;
};
//Wrapper for a React based client to redirect an anonymous user to CentralAuth when visiting a page that requires authentication
export const withCentralAuthAutomaticLogin = (Component, config = {}) => {
    return function withCentralAuthAutomaticLogin(props) {
        const { loginPath, profilePath } = config;
        const [user, setUser] = useState();
        useEffect(() => {
            fetch(profilePath || "/api/auth/me")
                .then(response => {
                response.json()
                    .then((userData) => {
                    if (userData == null)
                        window.location.replace(loginPath || "/api/auth/login");
                    else
                        setUser(userData);
                });
            });
        }, [loginPath, profilePath]);
        if (user)
            return React.createElement(Component, Object.assign({}, props));
        return null;
    };
};
