# eunox website

The public-facing website for eunox. Plain static HTML/CSS/JS — no build step,
no framework, no JS dependencies. It is meant to be servable from any static
host (GitHub Pages, S3, Cloudflare Pages, Netlify) or opened directly from
disk.

## Layout

```
web/
├── index.html           Landing page — hero, demo, features, how it works, CTA
├── quickstart.html      Step-by-step quick-start guide
├── features.html        Full eunox-mcp condition matrix with worked demos
├── how-it-works.html    Architecture, request flow, audit log internals
├── policies.html        Reference policies for popular MCP servers
├── docs.html            Documentation hub — links to repo docs and READMEs
└── assets/
    ├── styles.css       Shared styles (dark hero + light content)
    └── main.js          Terminal animation, copy-button, smooth scroll
```

## Local preview

```bash
# any static server will do
python3 -m http.server 8000 --directory web
# then open http://localhost:8000/
```

## Editing

- **Logo.** A single image URL is referenced from every page (`<header>`,
  `<footer>` and `<link rel="icon">`). Search for `user-attachments/assets`
  to find every reference.
- **Navigation.** Each page has the same `<header>` with a `nav-link.active`
  marker on the current page. When adding a page, copy the header from an
  existing page and update the active class.
- **Footer.** Identical across all pages — copy it verbatim when adding a
  new page.

## Authoritative sources

The website summarises material that lives elsewhere in the repo. When the
authoritative source changes, the website should be updated:

| Page               | Source of truth                                        |
|--------------------|--------------------------------------------------------|
| Quick start        | `README.md`, `docs/upgrade-to-hosted.md`               |
| Features           | `docs/capability-manifest-guide.md`, `docs/agent-sdk.md` |
| How it works       | `docs/architecture.md`, `docs/enforcement.md`          |
| Reference policies | `blogs/22-reference-policies.md`                       |
| Docs hub / links   | `docs/README.md`                                       |

## License

The website should reflect the dual-license split: BSL-1.1 for server-side services and Apache-2.0 for the `eunox-mcp` OSS tier.
