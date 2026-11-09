# eunolabs.ai placeholder

Single-page "coming soon" site for eunox on Cloudflare Pages. No build step.
Styles and logo are carried over from the earlier eunox site
(eunolabsx/eunox, `site/`).

- `public/` — the page, `styles.css`, `eunolabs.png`, `main.js` (waitlist form), `_headers`
- `functions/api/subscribe.js` — Pages Function behind the waitlist form; forwards
  the email to Buttondown (username `eunolabs`, override with the
  `BUTTONDOWN_USERNAME` env var on the Pages project). No API key needed.

## Deploy

    cd site
    npx wrangler pages deploy

The project is named `eunolabs-site`, same as the old site, so if that Pages
project still has `eunolabs.ai` attached under Custom Domains, this replaces
it in place. Otherwise create the project and add the domain in
Workers & Pages → eunolabs-site → Custom domains.

Or connect the repo in the dashboard: root directory `site`, build command
empty, output directory `public`.

The waitlist only works on the deployed site; under `file://` the form errors.
