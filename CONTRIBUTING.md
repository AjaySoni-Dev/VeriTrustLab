# Contributing to VeriTrust

## Before you start

- Open an issue for behavior changes that affect public routes, API contracts, billing, authentication, or stored data.
- Keep each pull request focused on one concern.
- Never include real credentials, personal scan data, database exports, or provider responses.

## Development workflow

1. Create a branch from `main`.
2. Run `npm ci`.
3. Create an ignored `.env.local` from the environment inventory in `README.md` when runtime testing is needed.
4. Make the smallest coherent change.
5. Run `npm run check` before committing.
6. Explain user-visible behavior, operational impact, and environment changes in the pull request.

## Repository conventions

- Keep public Vercel entrypoints in `api/` and private implementations in `lib/routes/`.
- Put reusable browser code in `assets/js/core/` and page controllers in `assets/js/pages/`.
- Put shared styles in `assets/css/base/` and page-specific styles in `assets/css/pages/`.
- Do not add copied version suffixes such as `feature-v2.js`; update the canonical file.
- Do not commit generated reports, temporary scripts, local SQL, database dumps, coverage, or build output.
- Do not commit model weights, local model conversions, provider captures, or benchmark fixtures containing sensitive content; use the approved artifact registry and the model-acquisition guide's pinning, licensing, and review process.
- Update documentation and the `README.md` environment inventory whenever configuration or deployment behavior changes.

## Security-sensitive changes

Authentication, authorization, API keys, billing, upload validation, webhook destinations, CSP, and tenant isolation require explicit review. Avoid weakening a control to make local testing easier.
