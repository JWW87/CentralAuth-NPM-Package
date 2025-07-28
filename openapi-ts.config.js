import { defineConfig } from '@hey-api/openapi-ts';
export default defineConfig({
    input: "https://centralauth.com/api/openapi",
    output: 'api',
    plugins: [
        '@hey-api/client-fetch',
        {
            name: '@hey-api/typescript',
            readOnlyWriteOnlyBehavior: 'off',
        },
        {
            name: '@hey-api/sdk',
        },
    ]
});
//# sourceMappingURL=openapi-ts.config.js.map