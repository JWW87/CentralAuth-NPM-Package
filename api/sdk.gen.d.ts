import type { Client, Options as ClientOptions, TDataShape } from '@hey-api/client-fetch';
import type { DeleteApiV1ApiKeyByIdData, DeleteApiV1InternalUserByTenantIdByUserIdData, DeleteApiV1InvitedUserByIdData, DeleteApiV1OrganizationByIdData, DeleteApiV1TenantByIdData, DeleteApiV1UserByIdData, DeleteApiV1UserByOrganizationIdByEmailData, GetApiV1ApiKeyByIdData, GetApiV1ApiKeysByOrganizationIdData, GetApiV1OrganizationByIdData, GetApiV1OrganizationByIdRotateSecretData, GetApiV1TenantByIdData, GetApiV1UserByIdData, GetApiV1UserByOrganizationIdByEmailData, GetApiV1UsersByOrganizationIdData, PostApiV1ApiKeyByIdData, PostApiV1ApiKeyData, PostApiV1InternalUserByTenantIdByUserIdData, PostApiV1InvitedUserData, PostApiV1OrganizationByIdActivateSecretData, PostApiV1OrganizationByIdData, PostApiV1OrganizationData, PostApiV1TenantByIdData, PostApiV1UserByIdData, PostApiV1UserByOrganizationIdByEmailData, PostApiV1UserData } from './types.gen';
export type Options<TData extends TDataShape = TDataShape, ThrowOnError extends boolean = boolean> = ClientOptions<TData, ThrowOnError> & {
  /**
   * You can provide a client instance returned by `createClient()` instead of
   * individual options. This might be also useful if you want to implement a
   * custom client.
   */
  client?: Client;
  /**
   * You can pass arbitrary values through the `meta` object. This can be
   * used to access values that aren't defined as part of the SDK function.
   */
  meta?: Record<string, unknown>;
};
/**
 * Delete an invited admin
 */
export declare const deleteApiV1InvitedUserById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1InvitedUserByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<unknown, unknown, ThrowOnError>;
/**
 * Invite an new admin to the tenant
 */
export declare const postApiV1InvitedUser: <ThrowOnError extends boolean = false>(options?: Options<PostApiV1InvitedUserData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").InvitedUser, unknown, ThrowOnError>;
/**
 * Delete an internal user (admin) on a tenant
 */
export declare const deleteApiV1InternalUserByTenantIdByUserId: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1InternalUserByTenantIdByUserIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<unknown, unknown, ThrowOnError>;
/**
 * Update an existing internal user (admin) on a tenant
 */
export declare const postApiV1InternalUserByTenantIdByUserId: <ThrowOnError extends boolean = false>(options: Options<PostApiV1InternalUserByTenantIdByUserIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").InternalUser, unknown, ThrowOnError>;
/**
 * Delete an organization
 * WARNING! When you delete an organizations, all users and settings will be deleted. This action cannot be undone.
 */
export declare const deleteApiV1OrganizationById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1OrganizationByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<unknown, unknown, ThrowOnError>;
/**
 * Get an organization
 */
export declare const getApiV1OrganizationById: <ThrowOnError extends boolean = false>(options: Options<GetApiV1OrganizationByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").Organization, unknown, ThrowOnError>;
/**
 * Update an existing organization
 */
export declare const postApiV1OrganizationById: <ThrowOnError extends boolean = false>(options: Options<PostApiV1OrganizationByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").Organization, unknown, ThrowOnError>;
/**
 * Create a new organization
 */
export declare const postApiV1Organization: <ThrowOnError extends boolean = false>(options?: Options<PostApiV1OrganizationData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").Organization, unknown, ThrowOnError>;
/**
 * Request a new client secret for the organization
 */
export declare const getApiV1OrganizationByIdRotateSecret: <ThrowOnError extends boolean = false>(options: Options<GetApiV1OrganizationByIdRotateSecretData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<string, unknown, ThrowOnError>;
/**
 * Activate the newly created client secret for the organization
 * To create a new client secret, first use the /api/v1/organization/{id}/rotate_secret endpoint.
 */
export declare const postApiV1OrganizationByIdActivateSecret: <ThrowOnError extends boolean = false>(options: Options<PostApiV1OrganizationByIdActivateSecretData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<unknown, unknown, ThrowOnError>;
/**
 * Delete a tenant
 * WARNING! When you delete a tenant, all organizations, users and settings will be deleted. This action cannot be undone.
 */
export declare const deleteApiV1TenantById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1TenantByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<unknown, unknown, ThrowOnError>;
/**
 * Get a tenant
 */
export declare const getApiV1TenantById: <ThrowOnError extends boolean = false>(options: Options<GetApiV1TenantByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").Tenant, unknown, ThrowOnError>;
/**
 * Update an existing tenant
 */
export declare const postApiV1TenantById: <ThrowOnError extends boolean = false>(options: Options<PostApiV1TenantByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").Tenant, unknown, ThrowOnError>;
/**
 * Delete a user
 * Note that a user can create a new user object by logging in again. It is not necessary to create a new user object first.
 */
export declare const deleteApiV1UserById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1UserByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<unknown, unknown, ThrowOnError>;
/**
 * Get a user
 */
export declare const getApiV1UserById: <ThrowOnError extends boolean = false>(options: Options<GetApiV1UserByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").User, unknown, ThrowOnError>;
/**
 * Update an existing user
 * Note that it is not possible to edit the email address of a user.
 */
export declare const postApiV1UserById: <ThrowOnError extends boolean = false>(options: Options<PostApiV1UserByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").User, unknown, ThrowOnError>;
/**
 * Delete a user by email address
 * Note that a user can create a new user object by logging in again. It is not necessary to create a new user object first.
 */
export declare const deleteApiV1UserByOrganizationIdByEmail: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1UserByOrganizationIdByEmailData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<unknown, unknown, ThrowOnError>;
/**
 * Get a user by email address
 */
export declare const getApiV1UserByOrganizationIdByEmail: <ThrowOnError extends boolean = false>(options: Options<GetApiV1UserByOrganizationIdByEmailData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").User, unknown, ThrowOnError>;
/**
 * Update an existing user by email address
 * Note that it is not possible to edit the email address of a user.
 */
export declare const postApiV1UserByOrganizationIdByEmail: <ThrowOnError extends boolean = false>(options: Options<PostApiV1UserByOrganizationIdByEmailData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").User, unknown, ThrowOnError>;
/**
 * Create a new user
 * Note that it is not necessary to create a user before this user can log in. When a user does not exist when they try to log for in the first time, the user will be created automatically.
 */
export declare const postApiV1User: <ThrowOnError extends boolean = false>(options?: Options<PostApiV1UserData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").User, unknown, ThrowOnError>;
/**
 * Get a list of users
 * Get a pager object with all users in an organization
 */
export declare const getApiV1UsersByOrganizationId: <ThrowOnError extends boolean = false>(options: Options<GetApiV1UsersByOrganizationIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<{
  pager: {
    pageIndex?: number;
    readonly pages: number;
    limitPerPage?: number;
    readonly totalEntities: number;
  };
  data: Array<import("./types.gen").User>;
}, unknown, ThrowOnError>;
/**
 * Delete an API key
 */
export declare const deleteApiV1ApiKeyById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1ApiKeyByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<unknown, unknown, ThrowOnError>;
/**
 * Get an API key
 */
export declare const getApiV1ApiKeyById: <ThrowOnError extends boolean = false>(options: Options<GetApiV1ApiKeyByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").ApiKey, unknown, ThrowOnError>;
/**
 * Update an existing API key
 */
export declare const postApiV1ApiKeyById: <ThrowOnError extends boolean = false>(options: Options<PostApiV1ApiKeyByIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").ApiKey, unknown, ThrowOnError>;
/**
 * Create a new API key
 */
export declare const postApiV1ApiKey: <ThrowOnError extends boolean = false>(options?: Options<PostApiV1ApiKeyData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").ApiKey, unknown, ThrowOnError>;
/**
 * Get all API keys for a tenant or organization
 */
export declare const getApiV1ApiKeysByOrganizationId: <ThrowOnError extends boolean = false>(options: Options<GetApiV1ApiKeysByOrganizationIdData, ThrowOnError>) => import("@hey-api/client-fetch").RequestResult<import("./types.gen").ApiKey[], unknown, ThrowOnError>;
