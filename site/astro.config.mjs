import { defineConfig } from 'astro/config';

const base = process.env.PUBLIC_BASE_PATH ?? '/';

export default defineConfig({
  site: 'https://eunolabs.ai',
  base,
  output: 'static',
});
