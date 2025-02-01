import { defineConfig } from '@hey-api/openapi-ts';

export default defineConfig({
  input: "https://centralauth.com/api/openapi",
  output: 'api',
  plugins: ['@hey-api/client-fetch']
});