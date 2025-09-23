import type { Options as ClientOptions, TDataShape, Client } from './client';
import type { DeleteApiV1InvitedUserByIdData, DeleteApiV1InvitedUserByIdResponses, DeleteApiV1InvitedUserByIdErrors, PostApiV1InvitedUserData, PostApiV1InvitedUserResponses, PostApiV1InvitedUserErrors, DeleteApiV1InternalUserByTenantIdByUserIdData, DeleteApiV1InternalUserByTenantIdByUserIdResponses, DeleteApiV1InternalUserByTenantIdByUserIdErrors, PostApiV1InternalUserByTenantIdByUserIdData, PostApiV1InternalUserByTenantIdByUserIdResponses, PostApiV1InternalUserByTenantIdByUserIdErrors, DeleteApiV1OrganizationByIdData, DeleteApiV1OrganizationByIdResponses, DeleteApiV1OrganizationByIdErrors, GetApiV1OrganizationByIdData, GetApiV1OrganizationByIdResponses, GetApiV1OrganizationByIdErrors, PostApiV1OrganizationByIdData, PostApiV1OrganizationByIdResponses, PostApiV1OrganizationByIdErrors, PostApiV1OrganizationData, PostApiV1OrganizationResponses, PostApiV1OrganizationErrors, GetApiV1OrganizationByIdRotateSecretData, GetApiV1OrganizationByIdRotateSecretResponses, GetApiV1OrganizationByIdRotateSecretErrors, PostApiV1OrganizationByIdActivateSecretData, PostApiV1OrganizationByIdActivateSecretResponses, PostApiV1OrganizationByIdActivateSecretErrors, DeleteApiV1TenantByIdData, DeleteApiV1TenantByIdResponses, DeleteApiV1TenantByIdErrors, GetApiV1TenantByIdData, GetApiV1TenantByIdResponses, GetApiV1TenantByIdErrors, PostApiV1TenantByIdData, PostApiV1TenantByIdResponses, PostApiV1TenantByIdErrors, GetApiV1InvoicesByTenantIdData, GetApiV1InvoicesByTenantIdResponses, GetApiV1InvoicesByTenantIdErrors, DeleteApiV1UserByIdData, DeleteApiV1UserByIdResponses, DeleteApiV1UserByIdErrors, GetApiV1UserByIdData, GetApiV1UserByIdResponses, GetApiV1UserByIdErrors, PostApiV1UserByIdData, PostApiV1UserByIdResponses, PostApiV1UserByIdErrors, DeleteApiV1UserByOrganizationIdByEmailData, DeleteApiV1UserByOrganizationIdByEmailResponses, DeleteApiV1UserByOrganizationIdByEmailErrors, GetApiV1UserByOrganizationIdByEmailData, GetApiV1UserByOrganizationIdByEmailResponses, GetApiV1UserByOrganizationIdByEmailErrors, PostApiV1UserByOrganizationIdByEmailData, PostApiV1UserByOrganizationIdByEmailResponses, PostApiV1UserByOrganizationIdByEmailErrors, PostApiV1UserData, PostApiV1UserResponses, PostApiV1UserErrors, GetApiV1UsersByOrganizationIdData, GetApiV1UsersByOrganizationIdResponses, GetApiV1UsersByOrganizationIdErrors, DeleteApiV1ApiKeyByIdData, DeleteApiV1ApiKeyByIdResponses, DeleteApiV1ApiKeyByIdErrors, GetApiV1ApiKeyByIdData, GetApiV1ApiKeyByIdResponses, GetApiV1ApiKeyByIdErrors, PostApiV1ApiKeyByIdData, PostApiV1ApiKeyByIdResponses, PostApiV1ApiKeyByIdErrors, PostApiV1ApiKeyData, PostApiV1ApiKeyResponses, PostApiV1ApiKeyErrors, GetApiV1ApiKeysByOrganizationIdData, GetApiV1ApiKeysByOrganizationIdResponses, GetApiV1ApiKeysByOrganizationIdErrors, GetApiV1ApiRequestsByTenantIdData, GetApiV1ApiRequestsByTenantIdResponses, GetApiV1ApiRequestsByTenantIdErrors, GetApiV1AuditLogsByTenantIdData, GetApiV1AuditLogsByTenantIdResponses, GetApiV1AuditLogsByTenantIdErrors } from './types.gen';
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
export declare const deleteApiV1InvitedUserById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1InvitedUserByIdData, ThrowOnError>) => import("./client").RequestResult<DeleteApiV1InvitedUserByIdResponses, DeleteApiV1InvitedUserByIdErrors, ThrowOnError, "fields">;
/**
 * Invite an new admin to the tenant
 */
export declare const postApiV1InvitedUser: <ThrowOnError extends boolean = false>(options?: Options<PostApiV1InvitedUserData, ThrowOnError>) => import("./client").RequestResult<PostApiV1InvitedUserResponses, PostApiV1InvitedUserErrors, ThrowOnError, "fields">;
/**
 * Delete an internal user (admin) on a tenant
 */
export declare const deleteApiV1InternalUserByTenantIdByUserId: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1InternalUserByTenantIdByUserIdData, ThrowOnError>) => import("./client").RequestResult<DeleteApiV1InternalUserByTenantIdByUserIdResponses, DeleteApiV1InternalUserByTenantIdByUserIdErrors, ThrowOnError, "fields">;
/**
 * Update an existing internal user (admin) on a tenant
 */
export declare const postApiV1InternalUserByTenantIdByUserId: <ThrowOnError extends boolean = false>(options: Options<PostApiV1InternalUserByTenantIdByUserIdData, ThrowOnError>) => import("./client").RequestResult<PostApiV1InternalUserByTenantIdByUserIdResponses, PostApiV1InternalUserByTenantIdByUserIdErrors, ThrowOnError, "fields">;
/**
 * Delete an organization
 * WARNING! When you delete an organizations, all users and settings will be deleted. This action cannot be undone.
 */
export declare const deleteApiV1OrganizationById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1OrganizationByIdData, ThrowOnError>) => import("./client").RequestResult<DeleteApiV1OrganizationByIdResponses, DeleteApiV1OrganizationByIdErrors, ThrowOnError, "fields">;
/**
 * Get an organization
 */
export declare const getApiV1OrganizationById: <ThrowOnError extends boolean = false>(options: Options<GetApiV1OrganizationByIdData, ThrowOnError>) => import("./client").RequestResult<GetApiV1OrganizationByIdResponses, GetApiV1OrganizationByIdErrors, ThrowOnError, "fields">;
/**
 * Update an existing organization
 */
export declare const postApiV1OrganizationById: <ThrowOnError extends boolean = false>(options: Options<PostApiV1OrganizationByIdData, ThrowOnError>) => import("./client").RequestResult<PostApiV1OrganizationByIdResponses, PostApiV1OrganizationByIdErrors, ThrowOnError, "fields">;
/**
 * Create a new organization
 */
export declare const postApiV1Organization: <ThrowOnError extends boolean = false>(options?: Options<PostApiV1OrganizationData, ThrowOnError>) => import("./client").RequestResult<PostApiV1OrganizationResponses, PostApiV1OrganizationErrors, ThrowOnError, "fields">;
/**
 * Request a new client secret for the organization
 */
export declare const getApiV1OrganizationByIdRotateSecret: <ThrowOnError extends boolean = false>(options: Options<GetApiV1OrganizationByIdRotateSecretData, ThrowOnError>) => import("./client").RequestResult<GetApiV1OrganizationByIdRotateSecretResponses, GetApiV1OrganizationByIdRotateSecretErrors, ThrowOnError, "fields">;
/**
 * Activate the newly created client secret for the organization
 * To create a new client secret, first use the /api/v1/organization/{id}/rotate_secret endpoint.
 */
export declare const postApiV1OrganizationByIdActivateSecret: <ThrowOnError extends boolean = false>(options: Options<PostApiV1OrganizationByIdActivateSecretData, ThrowOnError>) => import("./client").RequestResult<PostApiV1OrganizationByIdActivateSecretResponses, PostApiV1OrganizationByIdActivateSecretErrors, ThrowOnError, "fields">;
/**
 * Delete a tenant
 * WARNING! When you delete a tenant, all organizations, users and settings will be deleted. This action cannot be undone.
 */
export declare const deleteApiV1TenantById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1TenantByIdData, ThrowOnError>) => import("./client").RequestResult<DeleteApiV1TenantByIdResponses, DeleteApiV1TenantByIdErrors, ThrowOnError, "fields">;
/**
 * Get a tenant
 */
export declare const getApiV1TenantById: <ThrowOnError extends boolean = false>(options: Options<GetApiV1TenantByIdData, ThrowOnError>) => import("./client").RequestResult<GetApiV1TenantByIdResponses, GetApiV1TenantByIdErrors, ThrowOnError, "fields">;
/**
 * Update an existing tenant
 */
export declare const postApiV1TenantById: <ThrowOnError extends boolean = false>(options: Options<PostApiV1TenantByIdData, ThrowOnError>) => import("./client").RequestResult<PostApiV1TenantByIdResponses, PostApiV1TenantByIdErrors, ThrowOnError, "fields">;
/**
 * Get all invoices for a tenant
 */
export declare const getApiV1InvoicesByTenantId: <ThrowOnError extends boolean = false>(options: Options<GetApiV1InvoicesByTenantIdData, ThrowOnError>) => import("./client").RequestResult<GetApiV1InvoicesByTenantIdResponses, GetApiV1InvoicesByTenantIdErrors, ThrowOnError, "fields">;
/**
 * Delete a user
 * Note that a user can create a new user object by logging in again. It is not necessary to create a new user object first.
 */
export declare const deleteApiV1UserById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1UserByIdData, ThrowOnError>) => import("./client").RequestResult<DeleteApiV1UserByIdResponses, DeleteApiV1UserByIdErrors, ThrowOnError, "fields">;
/**
 * Get a user
 */
export declare const getApiV1UserById: <ThrowOnError extends boolean = false>(options: Options<GetApiV1UserByIdData, ThrowOnError>) => import("./client").RequestResult<GetApiV1UserByIdResponses, GetApiV1UserByIdErrors, ThrowOnError, "fields">;
/**
 * Update an existing user
 * Note that it is not possible to edit the email address of a user.
 */
export declare const postApiV1UserById: <ThrowOnError extends boolean = false>(options: Options<PostApiV1UserByIdData, ThrowOnError>) => import("./client").RequestResult<PostApiV1UserByIdResponses, PostApiV1UserByIdErrors, ThrowOnError, "fields">;
/**
 * Delete a user by email address
 * Note that a user can create a new user object by logging in again. It is not necessary to create a new user object first.
 */
export declare const deleteApiV1UserByOrganizationIdByEmail: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1UserByOrganizationIdByEmailData, ThrowOnError>) => import("./client").RequestResult<DeleteApiV1UserByOrganizationIdByEmailResponses, DeleteApiV1UserByOrganizationIdByEmailErrors, ThrowOnError, "fields">;
/**
 * Get a user by email address
 */
export declare const getApiV1UserByOrganizationIdByEmail: <ThrowOnError extends boolean = false>(options: Options<GetApiV1UserByOrganizationIdByEmailData, ThrowOnError>) => import("./client").RequestResult<GetApiV1UserByOrganizationIdByEmailResponses, GetApiV1UserByOrganizationIdByEmailErrors, ThrowOnError, "fields">;
/**
 * Update an existing user by email address
 * Note that it is not possible to edit the email address of a user.
 */
export declare const postApiV1UserByOrganizationIdByEmail: <ThrowOnError extends boolean = false>(options: Options<PostApiV1UserByOrganizationIdByEmailData, ThrowOnError>) => import("./client").RequestResult<PostApiV1UserByOrganizationIdByEmailResponses, PostApiV1UserByOrganizationIdByEmailErrors, ThrowOnError, "fields">;
/**
 * Create a new user
 * Note that it is not necessary to create a user before this user can log in. When a user does not exist when they try to log for in the first time, the user will be created automatically.
 */
export declare const postApiV1User: <ThrowOnError extends boolean = false>(options?: Options<PostApiV1UserData, ThrowOnError>) => import("./client").RequestResult<PostApiV1UserResponses, PostApiV1UserErrors, ThrowOnError, "fields">;
/**
 * Get a list of users
 * Get a pager object with all users in an organization
 */
export declare const getApiV1UsersByOrganizationId: <ThrowOnError extends boolean = false>(options: Options<GetApiV1UsersByOrganizationIdData, ThrowOnError>) => import("./client").RequestResult<GetApiV1UsersByOrganizationIdResponses, GetApiV1UsersByOrganizationIdErrors, ThrowOnError, "fields">;
/**
 * Delete an API key
 */
export declare const deleteApiV1ApiKeyById: <ThrowOnError extends boolean = false>(options: Options<DeleteApiV1ApiKeyByIdData, ThrowOnError>) => import("./client").RequestResult<DeleteApiV1ApiKeyByIdResponses, DeleteApiV1ApiKeyByIdErrors, ThrowOnError, "fields">;
/**
 * Get an API key
 */
export declare const getApiV1ApiKeyById: <ThrowOnError extends boolean = false>(options: Options<GetApiV1ApiKeyByIdData, ThrowOnError>) => import("./client").RequestResult<GetApiV1ApiKeyByIdResponses, GetApiV1ApiKeyByIdErrors, ThrowOnError, "fields">;
/**
 * Update an existing API key
 */
export declare const postApiV1ApiKeyById: <ThrowOnError extends boolean = false>(options: Options<PostApiV1ApiKeyByIdData, ThrowOnError>) => import("./client").RequestResult<PostApiV1ApiKeyByIdResponses, PostApiV1ApiKeyByIdErrors, ThrowOnError, "fields">;
/**
 * Create a new API key
 */
export declare const postApiV1ApiKey: <ThrowOnError extends boolean = false>(options?: Options<PostApiV1ApiKeyData, ThrowOnError>) => import("./client").RequestResult<PostApiV1ApiKeyResponses, PostApiV1ApiKeyErrors, ThrowOnError, "fields">;
/**
 * Get all API keys for a tenant or organization
 */
export declare const getApiV1ApiKeysByOrganizationId: <ThrowOnError extends boolean = false>(options: Options<GetApiV1ApiKeysByOrganizationIdData, ThrowOnError>) => import("./client").RequestResult<GetApiV1ApiKeysByOrganizationIdResponses, GetApiV1ApiKeysByOrganizationIdErrors, ThrowOnError, "fields">;
/**
 * Get a list of API requests
 * Get a list of API requests made under the given tenant.
 */
export declare const getApiV1ApiRequestsByTenantId: <ThrowOnError extends boolean = false>(options: Options<GetApiV1ApiRequestsByTenantIdData, ThrowOnError>) => import("./client").RequestResult<GetApiV1ApiRequestsByTenantIdResponses, GetApiV1ApiRequestsByTenantIdErrors, ThrowOnError, "fields">;
/**
 * Get a list of audit logs
 * Get a pager object with all audit logs created under a tenant
 */
export declare const getApiV1AuditLogsByTenantId: <ThrowOnError extends boolean = false>(options: Options<GetApiV1AuditLogsByTenantIdData, ThrowOnError>) => import("./client").RequestResult<GetApiV1AuditLogsByTenantIdResponses, GetApiV1AuditLogsByTenantIdErrors, ThrowOnError, "fields">;
