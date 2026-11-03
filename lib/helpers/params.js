import { strict as assert } from 'node:assert';

import omitBy from './_/omit_by.js';

const cache = new WeakMap();

export default function getParams(allowList) {
  if (!cache.has(allowList)) {
    assert(allowList, 'allowList must be present');

    const klass = class Params {
      constructor(params) {
        allowList.forEach((prop) => {
          this[prop] = params[prop] || undefined;

          /**
           * LOGTO PATCH(scope-space-normalization): drop the empty tokens produced by
           * leading, trailing, or repeated spaces (0x20 only) in `scope`, and treat a value
           * left empty as absent so the refresh grant falls back to the refresh token's own
           * scope (RFC 6749 §6). Clients such as OpenAI Codex send `scope=" offline_access"`.
           */
          if (prop === 'scope' && typeof this.scope === 'string') {
            this.scope = this.scope.split(' ').filter(Boolean).join(' ') || undefined;
          }
        });
      }

      toPlainObject() {
        return omitBy({ ...this }, (val) => typeof val === 'undefined');
      }
    };

    cache.set(allowList, klass);
  }

  return cache.get(allowList);
}
