# Fork patches

This branch (`v9`) tracks upstream [panva/node-oidc-provider](https://github.com/panva/node-oidc-provider) at the `v9.9.1` tag. Every deviation from that tag is documented here — one section per patch, added by the pull request that applies it. If a change is not in this file, it does not exist in the fork.

Each patch records four things:

- **What it does** — the behavior change, in one or two sentences.
- **Why upstream does not cover it** — the upstream decision or missing extension point that makes the patch necessary.
- **Files touched**
- **What breaks if dropped** — the observable failure that tells us the patch is missing.

## Repository scaffolding

### CI repository guards

- **What it does**: points the `github.repository == …` guards in the GitHub workflows at `logto-io/node-oidc-provider`, so the test, conformance, lock, and release jobs run in this fork instead of silently skipping. Also registers the `v9` branch in `test.yml`'s `push` and `pull_request` triggers, so the test suite runs for every PR targeting `v9`.
- **Why upstream does not cover it**: the guards hardcode `panva/node-oidc-provider`, and upstream only triggers on `main`.
- **Files touched**: `.github/workflows/conformance.yml`, `.github/workflows/lock.yml`, `.github/workflows/release.yml`, `.github/workflows/test.yml` (5 guards).
- **What breaks if dropped**: CI never runs on fork branches, so regressions land unnoticed.

## Library patches

None applied yet. Planned, in application order:

1. **Client-specific interaction UID** — carry over `interaction_cookie_handler.js` plus the small hunks in `#getInteraction` and `interactions.js`, so each client keeps its own interaction session cookie.
2. **Redirect URI validation relaxation** — minimal re-application after a requirements analysis; upstream 9.8.1 already relaxed the native custom-scheme rule, so only the still-needed lines return.
3. **`scope` always present in token, introspection, and userinfo-bearing responses** — three one-line hunks (`grant_common.js`, `introspection.js`, `jwt.js`) replacing upstream's `scope || undefined`.
