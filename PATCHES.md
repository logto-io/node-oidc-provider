# Fork patches

This branch (`v9`) tracks upstream [panva/node-oidc-provider](https://github.com/panva/node-oidc-provider) at the `v9.9.1` tag. Every deviation from that tag is documented here — one section per patch, added by the pull request that applies it. If a change is not in this file, it does not exist in the fork.

Each patch records four things:

- **What it does** — the behavior change, in one or two sentences.
- **Why upstream does not cover it** — the upstream decision or missing extension point that makes the patch necessary.
- **Files touched**
- **What breaks if dropped** — the observable failure that tells us the patch is missing.

To audit this inventory, run `git diff v9.9.1 --stat` on the branch: every file in that diff must appear in a **Files touched** list below (or be this file). The next upstream upgrade starts from that command and this document — re-apply each section onto the new tag, or retire it with a note here.

## Repository scaffolding

### CI repository guards

- **What it does**: points the `github.repository == …` guards in the GitHub workflows at `logto-io/node-oidc-provider`, so the test, conformance, lock, and release jobs run in this fork instead of silently skipping. Also registers the `v9` branch in `test.yml`'s `push` and `pull_request` triggers, so the test suite runs for every PR targeting `v9`.
- **Why upstream does not cover it**: the guards hardcode `panva/node-oidc-provider`, and upstream only triggers on `main`.
- **Files touched**: `.github/workflows/conformance.yml`, `.github/workflows/lock.yml`, `.github/workflows/release.yml`, `.github/workflows/test.yml` (5 guards).
- **What breaks if dropped**: CI never runs on fork branches, so regressions land unnoticed.

## Library patches

### Client-specific interaction UID — `LOGTO PATCH(client-specific-interaction-uid)`

- **What it does**: turns the interaction cookie value into a JSON mapping of client IDs to interaction UIDs, so concurrent sign-ins from different clients each resolve their own interaction. The requesting client is identified by the `Logto-App-Id` header (requests sent by the Logto Experience UI) or the `app_id` query parameter; a plain-string cookie from before the patch keeps working through a `_legacy` key. The mapping is stored percent-encoded — raw JSON is not a valid RFC 6265 cookie-value and strict servers (hapi, for one) reject the whole request over it; both pre-encoding formats (plain UID and the v8 fork's raw JSON) remain readable. The mapping is bounded on every write (at most 10 client entries and 3072 encoded bytes, evicting the least recently written entries first; `_legacy` survives eviction, and when a single entry alone cannot fit the size bound the mapping falls back to `_legacy` only, keeping the written interaction resolvable): CIMD client IDs are full URLs (~300 escaped bytes per entry), and an unbounded map silently overflows the ~4 KB per-cookie browser limit, dropping the whole Set-Cookie. Oversized cookies written before the bound existed shrink on their next write; the stored format is unchanged, so bounded and unbounded versions read each other's cookies.
- **Why upstream does not cover it**: there is no upstream equivalent feature, and the resolution point is a private class method (`Provider.#getInteraction`), unreachable from outside the library.
- **Files touched**: `lib/helpers/interaction_cookie_handler.js` (new), `lib/actions/authorization/interactions.js`, `lib/provider.js`; tests in `test/client_specific_interaction_uid/`, plus two hunks in the shared harness `test/test_helper.js` (the interaction cookie now holds the mapping, so the harness resolves UIDs through `getInteractionUid`).
- **What breaks if dropped**: two applications signing in concurrently in the same browser overwrite each other's interaction cookie, and Logto Experience requests carrying `Logto-App-Id` resolve the wrong interaction or none at all.

### Scope always present — `LOGTO PATCH(scope-always-present)`

- **What it does**: token endpoint responses, introspection responses, and JWT access token payloads always carry the token's `scope` verbatim, instead of upstream's conditional omission (`source.scope ? at.scope : (at.scope || undefined)` and `scope || undefined`). Observable difference: an access token whose scope is empty (or whose source token had none) still yields a `scope` member; `undefined` scopes still drop out of the JSON as before.
- **Why upstream does not cover it**: RFC 6749 §5.1 only requires `scope` in the response when it differs from the request, and upstream has omitted falsy scopes since the v8.4.0 RAR refactor (`e9fb5735`). Logto clients rely on `scope` always being echoed. This re-applies the v8 fork patches `4b621adf` and `de2d8fd6`.
- **Files touched**: `lib/helpers/grant_common.js` (`buildTokenResponse`, shared by the authorization_code, ciba, device_code, and refresh_token grants), `lib/actions/grants/client_credentials.js`, `lib/actions/introspection.js`, `lib/models/formats/jwt.js`; tests in `test/scope_always_present/`. One hunk more than originally planned: `client_credentials` builds its response body without `buildTokenResponse`, so it carries its own hunk (behaviorally inert in v9 — its token scope is never an empty string — but kept so every response site shares the same invariant).
- **What breaks if dropped**: responses for empty-scope tokens lose the `scope` member and `test/scope_always_present/` fails.

### Redirect URI validation relaxation — `LOGTO PATCH(redirect-uri-relaxation)`

- **What it does**: lifts the application_type-specific redirect URI shape restrictions in client metadata validation — web clients may register custom-scheme URIs (not only http/https), native clients may register non-loopback `http` URIs and loopback `https` URIs. Upstream's forbidden-scheme check (`javascript:`, `vbscript:`, `data:`, `blob:`, `file:`, `about:`), which only guarded native clients, now applies to both application types; the implicit-flow checks are untouched (Logto never issues the `implicit` grant type, so they are inert). This is a deliberate narrowing of the v8 fork patch (`20bcee8f`, #2): upstream 9.8.1 already dropped the reverse-domain requirement for native custom schemes, and the forbidden-scheme backstop is kept even though v8 allowed those schemes — none of them can serve as a working redirect target for a real application.
- **Why upstream does not cover it**: the checks implement RFC 8252 / OIDC registration best-practice recommendations with no configuration or extension point. Logto validates redirect URIs in its own Console and Management API layer, which accepts any http, https, or custom-scheme URI for every application type and surfaces best-practice warnings in the UI instead. This schema also runs every time a client is loaded from the adapter, so a stricter fork check would not just reject new registrations — it would break sign-in for applications Logto has already accepted.
- **Files touched**: `lib/helpers/client_schema.js`; test expectations adjusted in `test/configuration/client_metadata.test.js` and `test/oauth_native_apps/oauth_native_apps.test.js` (including a pin that wildcard-shaped `https://*.example.com/callback` URIs pass schema validation untouched — see the wildcard note below).
- **What breaks if dropped**: existing Logto applications with a custom-scheme web redirect URI (e.g. `capacitor://localhost`), a non-loopback `http` native URI, or a loopback `https` native URI fail client-load validation with `invalid_redirect_uri` / `invalid_client_metadata` and can no longer sign in.

### ID token claims effective scope — `LOGTO PATCH(id-token-claims-effective-scope)`

- **What it does**: `issueIdToken` queries the account claims callback (`findAccount(...).claims(use, scope, ...)`) with the effective scope of the current request — `scopeOverride || source.scopes` — instead of the source token's full stored scope. Observable difference: a down-scoped refresh request (e.g. `scope=openid` against a refresh token issued for `openid email offline_access`) now passes the narrowed scope to the claims callback. The other grants are unaffected: only the refresh_token grant passes `scopeOverride`, and for the rest `[...scopes].join(' ')` reconstructs `source.scope` exactly (`scopes` is derived from it).
- **Why upstream does not cover it**: for upstream's claims mechanism the two scopes are interchangeable — the IdToken mask filters the payload by the effective scope either way, so upstream's tests cannot observe a difference. Claim sources that load data per scope (as Logto's does, with per-scope database queries for roles, organizations, and SSO identities) would otherwise over-fetch on down-scoped refresh requests, and fail them on errors from queries the request no longer needs.
- **Files touched**: `lib/helpers/grant_common.js` (`issueIdToken`, one expression); tests in `test/id_token_claims_effective_scope/`.
- **What breaks if dropped**: down-scoped refresh requests query claim data for scopes the request no longer carries, and `test/id_token_claims_effective_scope/` fails.

### CIMD metadata transform — `LOGTO PATCH(cimd-metadata-transform)`

- **What it does**: adds a `features.clientIdMetadataDocument.transformClientMetadata(ctx, metadata)` helper, invoked on every Client ID Metadata Document resolution — fresh fetch and cache hit alike — after the document passes the draft-02 checks and before the Client instance is constructed. The hook receives a copy of the raw document and returns the metadata the Client is built from; the cache keeps the untouched document, the returned value still goes through the regular client schema validation, and errors thrown by the hook propagate untouched (a failing host callback is a server fault, not an `invalid_client`). The default is identity, and the feature's `ack: 'draft-02'` contract is unchanged.
- **Why upstream does not cover it**: upstream's CIMD extension points (`allowFetch`, `allowClient`) can only accept or reject a resolution; nothing can change what the Client instance is constructed from. Logto needs to take over `scope` and `grant_types` server-side (tenant ceiling and grant normalization, LOG-13923), and the override must apply on every resolution so host state changes take effect immediately regardless of cache TTL.
- **Files touched**: `lib/helpers/client_id_metadata_document.js`, `lib/helpers/defaults.js`; tests in `test/cimd_metadata_transform/`.
- **What breaks if dropped**: the configured helper is silently ignored — CIMD clients keep their remote document's self-declared `scope` and `grant_types`, Logto's server-side takeover (LOG-13923) stops applying, and `test/cimd_metadata_transform/` fails.

### Ensure session save persisted-only — `LOGTO PATCH(ensure-session-save-persisted-only)`

- **What it does**: `ensureSessionSave` only calls `session.persist()` when the session carries an `exp`, i.e. when it was persisted before. Observable difference: a request to a device user-code route that fails while carrying no persisted session responds with its intended error (a redirect to the Logto Experience device page, or upstream's rendered user-code form) instead of a 500. Sessions that were already persisted still get persisted exactly as before.
- **Why upstream does not cover it**: this is an upstream bug, not a Logto preference — `ensureSessionSave`'s condition (`touched && !destroyed`) is wider than `persist()`'s own precondition (`typeof exp === 'number'`, [`lib/models/session.js`](lib/models/session.js)), so the two disagree for a session that was touched but never persisted. `code_verification` and `device_resume` are the only routes whose error handler writes to the session (`generateXsrf` in [`lib/shared/error_handler.js`](lib/shared/error_handler.js)), and that write happens outside `sessionMiddleware`, whose own `save()` would otherwise cover it. Upstream v8 never surfaced the resulting `TypeError` because a provider-wide error handler wrapped the router and swallowed it; v9 dropped that backstop, so the error escapes the provider. Reported upstream; retire this patch once a fix lands there.
- **Files touched**: `lib/helpers/initialize_app.js` (`ensureSessionSave`, one condition); tests in `test/ensure_session_save/`.
- **What breaks if dropped**: `GET /device/:uid` and `POST /device` without a persisted session (cookie-less browsers, bookmarked resume URLs, scanners) respond 500 with `TypeError: persist can only be called on previously persisted Sessions`, and `test/ensure_session_save/` fails.

Deliberately **not** returning to the fork: the v8 wildcard redirect URI patch (#18, `11070941`). Its matching logic moves into Logto core, which overrides `Client.prototype.redirectUriAllowed` / `postLogoutRedirectUriAllowed` per provider instance (tracked as LOG-13813). Until that override lands, this branch accepts wildcard-shaped URIs at registration but matches redirect URIs exactly — Logto must not consume the v9 fork before LOG-13813 completes. A Logto-side end-to-end test (sign-in through a wildcard-registered URI) fails loudly if this dependency is violated.
