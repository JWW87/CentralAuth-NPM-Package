import { defineConfig } from '@hey-api/openapi-ts';

export default defineConfig({
  input: "https://centralauth.com/api/openapi",
  output: 'api',
  parser: {
    transforms: {
      readWrite: {
        enabled: true
      }
    }
  },
  plugins: [
    '@hey-api/client-fetch',
    {
      name: '@hey-api/typescript'
    },
    {
      name: '@hey-api/sdk',
    },
  ]
});