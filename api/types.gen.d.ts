export type InvitedUser = {
    readonly id?: string;
    tenantId: string;
    email: string;
    roleId: 'Admin' | 'OrganizationAdmin' | 'FinancialAdmin' | 'UserAdmin';
    readonly activated?: boolean;
    readonly created?: string;
    readonly updated?: string;
    role: {
        id?: 'Admin' | 'OrganizationAdmin' | 'FinancialAdmin' | 'UserAdmin';
        name: string;
    };
};
export type InternalUser = {
    readonly tenantId?: string;
    readonly userId?: string;
    roleId: 'Admin' | 'OrganizationAdmin' | 'FinancialAdmin' | 'UserAdmin';
};
export type OrganizationSettings = {
    readonly id?: string;
    maxSessionTime?: number;
    maxInactivityTime?: number;
    allowLocalhost?: boolean;
    checkReferrer?: boolean;
    hijackProtection?: boolean;
    autoLogin?: boolean;
    defaultLoginMethod?: 'local' | 'remote' | 'userPick';
    defaultLoginAttemptType?: 'link' | 'challenge' | 'code';
    useGlobalSmtp?: boolean;
    smtpHost?: string | null;
    smtpPort?: number | null;
    smtpFrom?: string | null;
    smtpUser?: string | null;
    smtpPass?: string | null;
};
export type WhitelistItem = {
    readonly id?: string;
    readonly organizationId?: string;
    value: string;
};
export type OAuthProvider = {
    readonly id?: string;
    readonly organizationId?: string;
    type: 'google' | 'apple' | 'microsoft' | 'github';
    useOwnCredentials?: boolean;
    clientId: string | null;
    clientSecret: string | null;
};
export type Organization = {
    readonly id?: string;
    tenantId: string;
    name: string;
    logo?: string | null;
    /**
     * The client secret key for the organization. When creating a new organization, the client secret will be readable once. After that, the client secret will be encrypted and cannot be retrieved.
     */
    readonly clientSecret?: string;
    customDomain?: string | null;
    overrideParentSettings?: boolean;
    readonly organizationSettingsId?: string;
    readonly created?: string;
    readonly updated?: string;
    settings?: OrganizationSettings;
    whitelistItems?: Array<WhitelistItem>;
    oAuthProviders?: Array<OAuthProvider>;
};
export type Role = {
    id?: 'Admin' | 'OrganizationAdmin' | 'FinancialAdmin' | 'UserAdmin';
    name: string;
    permissions: Array<{
        id?: 'updateTenant' | 'deleteTenant' | 'createOrganization' | 'updateOrganization' | 'deleteOrganization' | 'createUser' | 'updateUser' | 'deleteUser' | 'viewAllUsers';
        name?: string;
    }>;
};
export type Tenant = {
    readonly id?: string;
    readonly tenantId?: string;
    formId: string;
    name: string;
    logo?: string | null;
    readonly clientSecret?: string;
    readonly customDomain?: string;
    overrideParentSettings?: boolean;
    readonly organizationSettingsId?: string;
    readonly created?: string;
    readonly updated?: string;
    readonly internalUsers?: Array<InternalUser & {
        user: {
            readonly id?: string;
            /**
             * An email address unique for this user.
             */
            email: string;
            /**
             * The Gravatar image URL.
             */
            readonly gravatar?: string;
            /**
             * Flag whether this user has verified their email address.
             */
            verified?: boolean;
            /**
             * Flag whether this user is blocked.
             */
            blocked?: boolean;
            organizationId: string;
            readonly created?: string;
            readonly updated?: string;
        };
    } & {
        role: Role;
    }>;
    readonly invitedUsers?: Array<InvitedUser>;
    settings?: OrganizationSettings;
};
export type User = {
    readonly id?: string;
    /**
     * An email address unique for this user.
     */
    email: string;
    /**
     * The Gravatar image URL.
     */
    readonly gravatar?: string;
    /**
     * Flag whether this user has verified their email address.
     */
    verified?: boolean;
    /**
     * Flag whether this user is blocked.
     */
    blocked?: boolean;
    organizationId: string;
    readonly created?: string;
    readonly updated?: string;
    readonly connections?: Array<{
        id?: string;
        type?: 'email' | 'passkey' | 'google' | 'apple' | 'microsoft' | 'github';
        userId?: string;
        readonly created?: string;
        readonly updated?: string;
    }>;
};
export type ApiKey = {
    readonly id?: string;
    /**
     * Foreign key to a tenant or an organization.
     */
    organizationId: string;
    /**
     * The human-readable name of the API key.
     */
    name: string;
    /**
     * The hashed API key. When creating a new API key, it will be readable once. After that, the API key will be encrypted and cannot be retrieved.
     */
    readonly key?: string;
    readonly created?: string;
    readonly updated?: string;
    readonly lastUsed?: string;
};
export type DeleteApiV1InvitedUserByIdData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/invited_user/{id}';
};
export type DeleteApiV1InvitedUserByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type DeleteApiV1InvitedUserByIdError = DeleteApiV1InvitedUserByIdErrors[keyof DeleteApiV1InvitedUserByIdErrors];
export type DeleteApiV1InvitedUserByIdResponses = {
    /**
     * Success
     */
    200: unknown;
};
export type PostApiV1InvitedUserData = {
    body?: {
        tenantId: string;
        email: string;
        roleId: 'Admin' | 'OrganizationAdmin' | 'FinancialAdmin' | 'UserAdmin';
    };
    path?: never;
    query?: never;
    url: '/api/v1/invited_user';
};
export type PostApiV1InvitedUserErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1InvitedUserError = PostApiV1InvitedUserErrors[keyof PostApiV1InvitedUserErrors];
export type PostApiV1InvitedUserResponses = {
    /**
     * An invited admin object
     */
    200: InvitedUser;
};
export type PostApiV1InvitedUserResponse = PostApiV1InvitedUserResponses[keyof PostApiV1InvitedUserResponses];
export type DeleteApiV1InternalUserByTenantIdByUserIdData = {
    body?: never;
    path: {
        tenantId: string;
        userId: string;
    };
    query?: never;
    url: '/api/v1/internal_user/{tenantId}/{userId}';
};
export type DeleteApiV1InternalUserByTenantIdByUserIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type DeleteApiV1InternalUserByTenantIdByUserIdError = DeleteApiV1InternalUserByTenantIdByUserIdErrors[keyof DeleteApiV1InternalUserByTenantIdByUserIdErrors];
export type DeleteApiV1InternalUserByTenantIdByUserIdResponses = {
    /**
     * Success
     */
    200: unknown;
};
export type PostApiV1InternalUserByTenantIdByUserIdData = {
    body?: {
        roleId?: 'Admin' | 'OrganizationAdmin' | 'FinancialAdmin' | 'UserAdmin';
    };
    path: {
        tenantId: string;
        userId: string;
    };
    query?: never;
    url: '/api/v1/internal_user/{tenantId}/{userId}';
};
export type PostApiV1InternalUserByTenantIdByUserIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1InternalUserByTenantIdByUserIdError = PostApiV1InternalUserByTenantIdByUserIdErrors[keyof PostApiV1InternalUserByTenantIdByUserIdErrors];
export type PostApiV1InternalUserByTenantIdByUserIdResponses = {
    /**
     * An internal user object
     */
    200: InternalUser;
};
export type PostApiV1InternalUserByTenantIdByUserIdResponse = PostApiV1InternalUserByTenantIdByUserIdResponses[keyof PostApiV1InternalUserByTenantIdByUserIdResponses];
export type DeleteApiV1OrganizationByIdData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/organization/{id}';
};
export type DeleteApiV1OrganizationByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type DeleteApiV1OrganizationByIdError = DeleteApiV1OrganizationByIdErrors[keyof DeleteApiV1OrganizationByIdErrors];
export type DeleteApiV1OrganizationByIdResponses = {
    /**
     * Success
     */
    200: unknown;
};
export type GetApiV1OrganizationByIdData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/organization/{id}';
};
export type GetApiV1OrganizationByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type GetApiV1OrganizationByIdError = GetApiV1OrganizationByIdErrors[keyof GetApiV1OrganizationByIdErrors];
export type GetApiV1OrganizationByIdResponses = {
    /**
     * An organization object with whitelist items, OAuth providers and settings
     */
    200: Organization;
};
export type GetApiV1OrganizationByIdResponse = GetApiV1OrganizationByIdResponses[keyof GetApiV1OrganizationByIdResponses];
export type PostApiV1OrganizationByIdData = {
    body?: {
        name?: string;
        logo?: string | null;
        customDomain?: string | null;
        overrideParentSettings?: boolean;
        settings?: {
            maxSessionTime?: number;
            maxInactivityTime?: number;
            allowLocalhost?: boolean;
            checkReferrer?: boolean;
            hijackProtection?: boolean;
            autoLogin?: boolean;
            defaultLoginMethod?: 'local' | 'remote' | 'userPick';
            defaultLoginAttemptType?: 'link' | 'challenge' | 'code';
            useGlobalSmtp?: boolean;
            smtpHost?: string | null;
            smtpPort?: number | null;
            smtpFrom?: string | null;
            smtpUser?: string | null;
            smtpPass?: string | null;
        };
        whitelistItems?: Array<{
            value: string;
        }>;
        oAuthProviders?: Array<{
            type?: 'google' | 'apple' | 'microsoft' | 'github';
            useOwnCredentials?: boolean;
            clientId?: string | null;
            clientSecret?: string | null;
        }>;
    };
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/organization/{id}';
};
export type PostApiV1OrganizationByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1OrganizationByIdError = PostApiV1OrganizationByIdErrors[keyof PostApiV1OrganizationByIdErrors];
export type PostApiV1OrganizationByIdResponses = {
    /**
     * An organization object with whitelist items, OAuth providers and settings
     */
    200: Organization;
};
export type PostApiV1OrganizationByIdResponse = PostApiV1OrganizationByIdResponses[keyof PostApiV1OrganizationByIdResponses];
export type PostApiV1OrganizationData = {
    body?: {
        tenantId: string;
        name: string;
        logo?: string | null;
        customDomain?: string | null;
        overrideParentSettings?: boolean;
        settings?: {
            maxSessionTime?: number;
            maxInactivityTime?: number;
            allowLocalhost?: boolean;
            checkReferrer?: boolean;
            hijackProtection?: boolean;
            autoLogin?: boolean;
            defaultLoginMethod?: 'local' | 'remote' | 'userPick';
            defaultLoginAttemptType?: 'link' | 'challenge' | 'code';
            useGlobalSmtp?: boolean;
            smtpHost?: string | null;
            smtpPort?: number | null;
            smtpFrom?: string | null;
            smtpUser?: string | null;
            smtpPass?: string | null;
        };
        whitelistItems?: Array<{
            value: string;
        }>;
        oAuthProviders?: Array<{
            type: 'google' | 'apple' | 'microsoft' | 'github';
            useOwnCredentials?: boolean;
            clientId: string | null;
            clientSecret: string | null;
        }>;
    };
    path?: never;
    query?: never;
    url: '/api/v1/organization';
};
export type PostApiV1OrganizationErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1OrganizationError = PostApiV1OrganizationErrors[keyof PostApiV1OrganizationErrors];
export type PostApiV1OrganizationResponses = {
    /**
     * An organization object with whitelist items, OAuth providers and settings
     */
    200: Organization;
};
export type PostApiV1OrganizationResponse = PostApiV1OrganizationResponses[keyof PostApiV1OrganizationResponses];
export type GetApiV1OrganizationByIdRotateSecretData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/organization/{id}/rotate_secret';
};
export type GetApiV1OrganizationByIdRotateSecretErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type GetApiV1OrganizationByIdRotateSecretError = GetApiV1OrganizationByIdRotateSecretErrors[keyof GetApiV1OrganizationByIdRotateSecretErrors];
export type GetApiV1OrganizationByIdRotateSecretResponses = {
    /**
     * A new client secret for the organization. The client secret will be encrypted and cannot be retrieved after this request.
     */
    200: string;
};
export type GetApiV1OrganizationByIdRotateSecretResponse = GetApiV1OrganizationByIdRotateSecretResponses[keyof GetApiV1OrganizationByIdRotateSecretResponses];
export type PostApiV1OrganizationByIdActivateSecretData = {
    body?: string;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/organization/{id}/activate_secret';
};
export type PostApiV1OrganizationByIdActivateSecretErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1OrganizationByIdActivateSecretError = PostApiV1OrganizationByIdActivateSecretErrors[keyof PostApiV1OrganizationByIdActivateSecretErrors];
export type PostApiV1OrganizationByIdActivateSecretResponses = {
    /**
     * Success
     */
    200: unknown;
};
export type DeleteApiV1TenantByIdData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/tenant/{id}';
};
export type DeleteApiV1TenantByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type DeleteApiV1TenantByIdError = DeleteApiV1TenantByIdErrors[keyof DeleteApiV1TenantByIdErrors];
export type DeleteApiV1TenantByIdResponses = {
    /**
     * Success
     */
    200: unknown;
};
export type GetApiV1TenantByIdData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/tenant/{id}';
};
export type GetApiV1TenantByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type GetApiV1TenantByIdError = GetApiV1TenantByIdErrors[keyof GetApiV1TenantByIdErrors];
export type GetApiV1TenantByIdResponses = {
    /**
     * A tenant object with settings, internal and invited users.
     */
    200: Tenant;
};
export type GetApiV1TenantByIdResponse = GetApiV1TenantByIdResponses[keyof GetApiV1TenantByIdResponses];
export type PostApiV1TenantByIdData = {
    body?: {
        name?: string;
        logo?: string | null;
        settings?: OrganizationSettings;
    };
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/tenant/{id}';
};
export type PostApiV1TenantByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1TenantByIdError = PostApiV1TenantByIdErrors[keyof PostApiV1TenantByIdErrors];
export type PostApiV1TenantByIdResponses = {
    /**
     * A tenant object with settings, internal and invited users.
     */
    200: Tenant;
};
export type PostApiV1TenantByIdResponse = PostApiV1TenantByIdResponses[keyof PostApiV1TenantByIdResponses];
export type DeleteApiV1UserByIdData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/user/{id}';
};
export type DeleteApiV1UserByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type DeleteApiV1UserByIdError = DeleteApiV1UserByIdErrors[keyof DeleteApiV1UserByIdErrors];
export type DeleteApiV1UserByIdResponses = {
    /**
     * Success
     */
    200: unknown;
};
export type GetApiV1UserByIdData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/user/{id}';
};
export type GetApiV1UserByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type GetApiV1UserByIdError = GetApiV1UserByIdErrors[keyof GetApiV1UserByIdErrors];
export type GetApiV1UserByIdResponses = {
    /**
     * A user object with all active connections
     */
    200: User;
};
export type GetApiV1UserByIdResponse = GetApiV1UserByIdResponses[keyof GetApiV1UserByIdResponses];
export type PostApiV1UserByIdData = {
    body?: {
        /**
         * Flag whether this user has verified their email address.
         */
        verified?: boolean;
        /**
         * Flag whether this user is blocked.
         */
        blocked?: boolean;
    };
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/user/{id}';
};
export type PostApiV1UserByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1UserByIdError = PostApiV1UserByIdErrors[keyof PostApiV1UserByIdErrors];
export type PostApiV1UserByIdResponses = {
    /**
     * A user object with all active connections
     */
    200: User;
};
export type PostApiV1UserByIdResponse = PostApiV1UserByIdResponses[keyof PostApiV1UserByIdResponses];
export type DeleteApiV1UserByOrganizationIdByEmailData = {
    body?: never;
    path: {
        organizationId: string;
        email: string;
    };
    query?: never;
    url: '/api/v1/user/{organizationId}/{email}';
};
export type DeleteApiV1UserByOrganizationIdByEmailErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type DeleteApiV1UserByOrganizationIdByEmailError = DeleteApiV1UserByOrganizationIdByEmailErrors[keyof DeleteApiV1UserByOrganizationIdByEmailErrors];
export type DeleteApiV1UserByOrganizationIdByEmailResponses = {
    /**
     * Success
     */
    200: unknown;
};
export type GetApiV1UserByOrganizationIdByEmailData = {
    body?: never;
    path: {
        organizationId: string;
        email: string;
    };
    query?: never;
    url: '/api/v1/user/{organizationId}/{email}';
};
export type GetApiV1UserByOrganizationIdByEmailErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type GetApiV1UserByOrganizationIdByEmailError = GetApiV1UserByOrganizationIdByEmailErrors[keyof GetApiV1UserByOrganizationIdByEmailErrors];
export type GetApiV1UserByOrganizationIdByEmailResponses = {
    /**
     * A user object with all active connections
     */
    200: User;
};
export type GetApiV1UserByOrganizationIdByEmailResponse = GetApiV1UserByOrganizationIdByEmailResponses[keyof GetApiV1UserByOrganizationIdByEmailResponses];
export type PostApiV1UserByOrganizationIdByEmailData = {
    body?: {
        /**
         * Flag whether this user has verified their email address.
         */
        verified?: boolean;
        /**
         * Flag whether this user is blocked.
         */
        blocked?: boolean;
    };
    path: {
        organizationId: string;
        email: string;
    };
    query?: never;
    url: '/api/v1/user/{organizationId}/{email}';
};
export type PostApiV1UserByOrganizationIdByEmailErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1UserByOrganizationIdByEmailError = PostApiV1UserByOrganizationIdByEmailErrors[keyof PostApiV1UserByOrganizationIdByEmailErrors];
export type PostApiV1UserByOrganizationIdByEmailResponses = {
    /**
     * A user object with all active connections
     */
    200: User;
};
export type PostApiV1UserByOrganizationIdByEmailResponse = PostApiV1UserByOrganizationIdByEmailResponses[keyof PostApiV1UserByOrganizationIdByEmailResponses];
export type PostApiV1UserData = {
    body?: {
        /**
         * An email address unique for this user.
         */
        email: string;
        /**
         * Flag whether this user has verified their email address.
         */
        verified?: boolean;
        /**
         * Flag whether this user is blocked.
         */
        blocked?: boolean;
        organizationId: string;
    };
    path?: never;
    query?: never;
    url: '/api/v1/user';
};
export type PostApiV1UserErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1UserError = PostApiV1UserErrors[keyof PostApiV1UserErrors];
export type PostApiV1UserResponses = {
    /**
     * A user object with all active connections
     */
    200: User;
};
export type PostApiV1UserResponse = PostApiV1UserResponses[keyof PostApiV1UserResponses];
export type GetApiV1UsersByOrganizationIdData = {
    body?: never;
    path: {
        organizationId: string;
    };
    query?: {
        /**
         * Current page index in the pager, starting at 0
         */
        pageIndex?: number;
        /**
         * Maximum number of entities on one page
         */
        limitPerPage?: number;
        order?: 'id' | 'email' | 'verified' | 'blocked' | 'created' | 'updated';
        sort?: 'asc' | 'desc';
        search?: string;
    };
    url: '/api/v1/users/{organizationId}';
};
export type GetApiV1UsersByOrganizationIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type GetApiV1UsersByOrganizationIdError = GetApiV1UsersByOrganizationIdErrors[keyof GetApiV1UsersByOrganizationIdErrors];
export type GetApiV1UsersByOrganizationIdResponses = {
    /**
     * A pager object with users
     */
    200: {
        pager: {
            /**
             * Current page index in the pager, starting at 0
             */
            pageIndex?: number;
            /**
             * Total number of pages based on the limit per page
             */
            readonly pages: number;
            /**
             * Maximum number of entities on one page
             */
            limitPerPage?: number;
            /**
             * Total number of entities
             */
            readonly totalEntities: number;
        };
        data: Array<User>;
    };
};
export type GetApiV1UsersByOrganizationIdResponse = GetApiV1UsersByOrganizationIdResponses[keyof GetApiV1UsersByOrganizationIdResponses];
export type DeleteApiV1ApiKeyByIdData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/api_key/{id}';
};
export type DeleteApiV1ApiKeyByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type DeleteApiV1ApiKeyByIdError = DeleteApiV1ApiKeyByIdErrors[keyof DeleteApiV1ApiKeyByIdErrors];
export type DeleteApiV1ApiKeyByIdResponses = {
    /**
     * Success
     */
    200: unknown;
};
export type GetApiV1ApiKeyByIdData = {
    body?: never;
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/api_key/{id}';
};
export type GetApiV1ApiKeyByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type GetApiV1ApiKeyByIdError = GetApiV1ApiKeyByIdErrors[keyof GetApiV1ApiKeyByIdErrors];
export type GetApiV1ApiKeyByIdResponses = {
    /**
     * An API key object
     */
    200: ApiKey;
};
export type GetApiV1ApiKeyByIdResponse = GetApiV1ApiKeyByIdResponses[keyof GetApiV1ApiKeyByIdResponses];
export type PostApiV1ApiKeyByIdData = {
    body?: {
        /**
         * The human-readable name of the API key.
         */
        name?: string;
    };
    path: {
        id: string;
    };
    query?: never;
    url: '/api/v1/api_key/{id}';
};
export type PostApiV1ApiKeyByIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1ApiKeyByIdError = PostApiV1ApiKeyByIdErrors[keyof PostApiV1ApiKeyByIdErrors];
export type PostApiV1ApiKeyByIdResponses = {
    /**
     * An API key object
     */
    200: ApiKey;
};
export type PostApiV1ApiKeyByIdResponse = PostApiV1ApiKeyByIdResponses[keyof PostApiV1ApiKeyByIdResponses];
export type PostApiV1ApiKeyData = {
    body?: {
        /**
         * Foreign key to a tenant or an organization.
         */
        organizationId: string;
        /**
         * The human-readable name of the API key.
         */
        name: string;
    };
    path?: never;
    query?: never;
    url: '/api/v1/api_key';
};
export type PostApiV1ApiKeyErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type PostApiV1ApiKeyError = PostApiV1ApiKeyErrors[keyof PostApiV1ApiKeyErrors];
export type PostApiV1ApiKeyResponses = {
    /**
     * An API key object
     */
    200: ApiKey;
};
export type PostApiV1ApiKeyResponse = PostApiV1ApiKeyResponses[keyof PostApiV1ApiKeyResponses];
export type GetApiV1ApiKeysByOrganizationIdData = {
    body?: never;
    path: {
        /**
         * Tenant or organization ID
         */
        organizationId: string;
    };
    query?: never;
    url: '/api/v1/api_keys/{organizationId}';
};
export type GetApiV1ApiKeysByOrganizationIdErrors = {
    /**
     * Bad request
     */
    400: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * No permission
     */
    403: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Not found
     */
    404: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Invalid method
     */
    405: {
        errorCode?: 'genericError' | 'noPermission' | 'missingFields' | 'sessionMissing' | 'sessionNotVerified' | 'sessionInactive' | 'sessionInvalid' | 'domainInvalid' | 'verificationStateInvalid' | 'loginAttemptMissing' | 'loginAttemptExpired' | 'loginAttemptInvalid' | 'passkeyDataMissing' | 'passkeyDataExpired' | 'passkeyDataInvalid' | 'passkeyWrongOrganization' | 'sessionExpired' | 'callbackUrlInvalid' | 'connectionMissing' | 'organizationIdMissing' | 'secretMissing' | 'authBaseUrlMissing' | 'callbackUrlMissing' | 'tokenMissing' | 'tokenInvalid' | 'captchaInvalid' | 'entityMissing' | 'entityInvalid';
        message?: string;
    };
    /**
     * Deployment error
     */
    502: unknown;
    /**
     * Service unavailable
     */
    503: unknown;
    /**
     * Gateway timeout
     */
    504: unknown;
};
export type GetApiV1ApiKeysByOrganizationIdError = GetApiV1ApiKeysByOrganizationIdErrors[keyof GetApiV1ApiKeysByOrganizationIdErrors];
export type GetApiV1ApiKeysByOrganizationIdResponses = {
    /**
     * An array with API key objects
     */
    200: Array<ApiKey>;
};
export type GetApiV1ApiKeysByOrganizationIdResponse = GetApiV1ApiKeysByOrganizationIdResponses[keyof GetApiV1ApiKeysByOrganizationIdResponses];
export type ClientOptions = {
    baseUrl: 'https://centralauth.com' | (string & {});
};
