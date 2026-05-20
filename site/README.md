# euno website (Astro)

The public-facing website for [eunolabs.ai](https://eunolabs.ai), built with [Astro](https://astro.build) as a static site generator.

## Layout

```
site/
├── astro.config.mjs         Astro config (output: static, site: https://eunolabs.ai)
├── public/                  Static assets served at the root
│   ├── eunolabs.png
│   ├── eunolabs.svg
│   ├── styles.css           Shared styles (dark hero + light content)
│   └── main.js              Terminal animation, copy-button, smooth scroll
└── src/
    ├── content/
    │   ├── config.ts        Content collection schema (blog)
    │   └── blog/            Blog posts (Markdown with front matter)
    ├── layouts/
    │   └── BaseLayout.astro Shared layout: HTML shell, header, footer
    └── pages/
        ├── index.astro      Landing page
        ├── quickstart.astro Quick-start guide
        ├── features.astro   Full condition matrix
        ├── how-it-works.astro Architecture & request flow
        ├── policies.astro   Reference policies for popular MCP servers
        ├── docs.astro       Documentation hub
        └── blog/
            ├── index.astro  Blog listing (newest first)
            └── [...slug].astro Individual blog post
```

## Local preview

```bash
cd site
npm install
npm run dev
# open http://localhost:4321/
```

## Build

```bash
cd site
npm run build
# output in site/dist/
```

Or from the repo root:

```bash
npm run build:site
```

## Pages

| URL | Source |
|-----|--------|
| `/` | `src/pages/index.astro` |
| `/quickstart` | `src/pages/quickstart.astro` |
| `/features` | `src/pages/features.astro` |
| `/how-it-works` | `src/pages/how-it-works.astro` |
| `/policies` | `src/pages/policies.astro` |
| `/docs` | `src/pages/docs.astro` |
| `/blog` | `src/pages/blog/index.astro` |
| `/blog/[slug]` | `src/pages/blog/[...slug].astro` |

## Blog posts

Blog posts live in `src/content/blog/` as Markdown files with YAML front matter (`title`, `description`, `pubDate`, `audience`). The canonical source of blog content is `../blogs/` — when editing a post, update the version in `src/content/blog/`.

## License

Apache-2.0, same as the rest of the euno open-source project.
