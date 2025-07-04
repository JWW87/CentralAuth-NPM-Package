// This file is auto-generated by @hey-api/openapi-ts
import { client as _heyApiClient } from './client.gen';
/**
 * Delete an invited admin
 */
export const deleteApiV1InvitedUserById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).delete(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/invited_user/{id}' }, options));
};
/**
 * Invite an new admin to the tenant
 */
export const postApiV1InvitedUser = (options) => {
    var _a;
    return ((_a = options === null || options === void 0 ? void 0 : options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/invited_user' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options === null || options === void 0 ? void 0 : options.headers) }));
};
/**
 * Delete an internal user (admin) on a tenant
 */
export const deleteApiV1InternalUserByTenantIdByUserId = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).delete(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/internal_user/{tenantId}/{userId}' }, options));
};
/**
 * Update an existing internal user (admin) on a tenant
 */
export const postApiV1InternalUserByTenantIdByUserId = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/internal_user/{tenantId}/{userId}' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options.headers) }));
};
/**
 * Delete an organization
 * WARNING! When you delete an organizations, all users and settings will be deleted. This action cannot be undone.
 */
export const deleteApiV1OrganizationById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).delete(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/organization/{id}' }, options));
};
/**
 * Get an organization
 */
export const getApiV1OrganizationById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).get(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/organization/{id}' }, options));
};
/**
 * Update an existing organization
 */
export const postApiV1OrganizationById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/organization/{id}' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options.headers) }));
};
/**
 * Create a new organization
 */
export const postApiV1Organization = (options) => {
    var _a;
    return ((_a = options === null || options === void 0 ? void 0 : options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/organization' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options === null || options === void 0 ? void 0 : options.headers) }));
};
/**
 * Request a new client secret for the organization
 */
export const getApiV1OrganizationByIdRotateSecret = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).get(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/organization/{id}/rotate_secret' }, options));
};
/**
 * Activate the newly created client secret for the organization
 * To create a new client secret, first use the /api/v1/organization/{id}/rotate_secret endpoint.
 */
export const postApiV1OrganizationByIdActivateSecret = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/organization/{id}/activate_secret' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options.headers) }));
};
/**
 * Delete a tenant
 * WARNING! When you delete a tenant, all organizations, users and settings will be deleted. This action cannot be undone.
 */
export const deleteApiV1TenantById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).delete(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/tenant/{id}' }, options));
};
/**
 * Get a tenant
 */
export const getApiV1TenantById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).get(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/tenant/{id}' }, options));
};
/**
 * Update an existing tenant
 */
export const postApiV1TenantById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/tenant/{id}' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options.headers) }));
};
/**
 * Delete a user
 * Note that a user can create a new user object by logging in again. It is not necessary to create a new user object first.
 */
export const deleteApiV1UserById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).delete(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/user/{id}' }, options));
};
/**
 * Get a user
 */
export const getApiV1UserById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).get(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/user/{id}' }, options));
};
/**
 * Update an existing user
 * Note that it is not possible to edit the email address of a user.
 */
export const postApiV1UserById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/user/{id}' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options.headers) }));
};
/**
 * Delete a user by email address
 * Note that a user can create a new user object by logging in again. It is not necessary to create a new user object first.
 */
export const deleteApiV1UserByOrganizationIdByEmail = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).delete(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/user/{organizationId}/{email}' }, options));
};
/**
 * Get a user by email address
 */
export const getApiV1UserByOrganizationIdByEmail = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).get(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/user/{organizationId}/{email}' }, options));
};
/**
 * Update an existing user by email address
 * Note that it is not possible to edit the email address of a user.
 */
export const postApiV1UserByOrganizationIdByEmail = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/user/{organizationId}/{email}' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options.headers) }));
};
/**
 * Create a new user
 * Note that it is not necessary to create a user before this user can log in. When a user does not exist when they try to log for in the first time, the user will be created automatically.
 */
export const postApiV1User = (options) => {
    var _a;
    return ((_a = options === null || options === void 0 ? void 0 : options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/user' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options === null || options === void 0 ? void 0 : options.headers) }));
};
/**
 * Get a list of users
 * Get a pager object with all users in an organization
 */
export const getApiV1UsersByOrganizationId = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).get(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/users/{organizationId}' }, options));
};
/**
 * Delete an API key
 */
export const deleteApiV1ApiKeyById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).delete(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/api_key/{id}' }, options));
};
/**
 * Get an API key
 */
export const getApiV1ApiKeyById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).get(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/api_key/{id}' }, options));
};
/**
 * Update an existing API key
 */
export const postApiV1ApiKeyById = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/api_key/{id}' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options.headers) }));
};
/**
 * Create a new API key
 */
export const postApiV1ApiKey = (options) => {
    var _a;
    return ((_a = options === null || options === void 0 ? void 0 : options.client) !== null && _a !== void 0 ? _a : _heyApiClient).post(Object.assign(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/api_key' }, options), { headers: Object.assign({ 'Content-Type': 'application/json' }, options === null || options === void 0 ? void 0 : options.headers) }));
};
/**
 * Get all API keys for a tenant or organization
 */
export const getApiV1ApiKeysByOrganizationId = (options) => {
    var _a;
    return ((_a = options.client) !== null && _a !== void 0 ? _a : _heyApiClient).get(Object.assign({ security: [
            {
                scheme: 'bearer',
                type: 'http'
            },
            {
                in: 'cookie',
                name: 'accessToken',
                type: 'apiKey'
            }
        ], url: '/api/v1/api_keys/{organizationId}' }, options));
};
//# sourceMappingURL=sdk.gen.js.map