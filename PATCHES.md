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

### Client-specific interaction UID — `LOGTO PATCH(client-specific-interaction-uid)`

- **What it does**: turns the interaction cookie value into a JSON mapping of client IDs to interaction UIDs, so concurrent sign-ins from different clients each resolve their own interaction. The requesting client is identified by the `Logto-App-Id` header (requests sent by the Logto Experience UI) or the `app_id` query parameter; a plain-string cookie from before the patch keeps working through a `_legacy` key. The mapping is stored percent-encoded — raw JSON is not a valid RFC 6265 cookie-value and strict servers (hapi, for one) reject the whole request over it; both pre-encoding formats (plain UID and the v8 fork's raw JSON) remain readable.
- **Why upstream does not cover it**: there is no upstream equivalent feature, and the resolution point is a private class method (`Provider.#getInteraction`), unreachable from outside the library.
- **Files touched**: `lib/helpers/interaction_cookie_handler.js` (new), `lib/actions/authorization/interactions.js`, `lib/provider.js`; tests in `test/client_specific_interaction_uid/`.
- **What breaks if dropped**: two applications signing in concurrently in the same browser overwrite each other's interaction cookie, and Logto Experience requests carrying `Logto-App-Id` resolve the wrong interaction or none at all.

Planned next, in application order:

1. **Redirect URI validation relaxation** — minimal re-application after a requirements analysis; upstream 9.8.1 already relaxed the native custom-scheme rule, so only the still-needed lines return.
2. **`scope` always present in token, introspection, and userinfo-bearing responses** — three one-line hunks (`grant_common.js`, `introspection.js`, `jwt.js`) replacing upstream's `scope || undefined`.
