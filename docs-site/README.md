# open·kritt docs site (Mintlify)

This folder is a self-contained [Mintlify](https://mintlify.com) docs project. Content is
Markdown/MDX, so it stays portable if we ever switch tools.

## Preview locally

```bash
cd docs-site
npm i -g mint      # Mintlify CLI
npm run dev        # serves at http://localhost:3001
npm run check-links    # dependency-free internal route and redirect check
npm run broken-links   # Mintlify's link checker, including redirect destinations
```

The repository's development script pins the docs to port **3001**. A bare `mint dev`
still uses Mintlify's default port **3000**; use `mint dev --port <n>` for a different
one-off port.

Branding lives in `logo/mark-accent.png` (navbar logo, accent `#ff5c3d`) and
`favicon.svg`; `style.css` enlarges the navbar logo via Mintlify's `nav-logo` hook.

## Connect & publish

1. Sign up at [mintlify.com](https://mintlify.com) (the **Starter/free** plan is enough —
   we don't use the AI assistant).
2. Install the **Mintlify GitHub app** on `Kritt-ai/open-kritt` and point it at this
   `docs-site/` directory. It redeploys on every push to `main`.

## Custom domain — `docs.kritt.ai`

1. In the Mintlify dashboard → **Settings → Custom domain**, add `docs.kritt.ai`.
2. In DNS, add a `CNAME` for `docs.kritt.ai` → the target Mintlify gives you
   (`<your-subdomain>.mintlify.site`).

To instead host at **`kritt.ai/docs`** (same domain), enable **"Host at /docs"** in the
dashboard and add a reverse-proxy rule on your main site (Mintlify has ready-made setups
for Cloudflare Workers / Vercel / nginx). The plain `/docs` path works on non-Enterprise;
arbitrary subpaths (e.g. `/help`) are Enterprise-only.

## Editing

- Pages live here as `.mdx`; nav + theme are in `docs.json`.
- Renamed pages must keep a permanent redirect in `docs.json`; CI rejects stale internal
  links, missing navigation pages, and invalid redirect destinations.
- Security guidance links to the authoritative repo documents
  (`docs/threat-model.md`, `SECURITY.md`). If we fully adopt Mintlify, decide on a
  single source of truth to avoid drift.
