import { InvalidRequest } from '../../helpers/errors.js';
import instance from '../../helpers/weak_cache.js';

/*
 * Checks that all requested prompts are supported and validates prompt none is not combined with
 * other prompts
 */
export default function checkPrompt(ctx, next) {
  addConsentPromptForCimdOfflineAccess(ctx); // LOGTO PATCH(cimd-offline-access-consent)

  if (ctx.oidc.params.prompt !== undefined) {
    const { prompts } = ctx.oidc;
    const supported = instance(ctx.oidc.provider).configuration.prompts;

    for (const prompt of prompts) {
      if (!supported.has(prompt)) {
        throw new InvalidRequest('unsupported prompt value requested');
      }
    }

    if (prompts.has('none') && prompts.size !== 1) {
      throw new InvalidRequest('prompt none must only be used alone');
    }
  }

  return next();
}

/**
 * LOGTO PATCH(cimd-offline-access-consent)
 * `checkScope` only keeps `offline_access` with `prompt=consent` (OIDC Core section 11), so CIMD
 * clients that omit it get `consent` added instead of losing the scope. `none` must stay alone.
 */
function addConsentPromptForCimdOfflineAccess(ctx) {
  const { client, params, prompts } = ctx.oidc;

  if (
    client.clientIdMetadataDocument !== true
    || !params.scope?.split(' ').includes('offline_access')
    || prompts.has('consent')
    || prompts.has('none')
  ) {
    return;
  }

  prompts.add('consent');
  params.prompt = [...prompts].join(' ');
}
