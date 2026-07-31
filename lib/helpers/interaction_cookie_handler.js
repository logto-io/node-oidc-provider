/**
 * LOGTO PATCH(client-specific-interaction-uid)
 *
 * Helper functions to manage client-specific interaction UIDs in a single cookie
 */

import difference from './_/difference.js';
import isPlainObject from './_/is_plain_object.js';

/**
 * Bounds applied to the mapping on every write, evicting the least recently written client
 * entries first. Browsers reject a Set-Cookie whose name+value exceeds ~4096 bytes, and every
 * cookie of the domain shares one Cookie request header against proxy limits (nginx defaults
 * to 8 KB per header line), so the encoded value has to stay well below both. CIMD client IDs
 * are full URLs (~300 bytes each once escaped), which is what makes the mapping outgrow the
 * cookie in the first place. The entry cap is hygiene rather than a size guard (ten nanoid
 * entries encode to ~400 bytes): interactions expire server-side within their TTL, so entries
 * past a handful are dead weight riding along on every request to the domain.
 */
const MAX_CLIENT_ENTRIES = 10;
const MAX_ENCODED_LENGTH = 3072;

/**
 * Parse the interaction cookie value into a client-to-uid mapping
 * @param {string|undefined} cookieValue - The raw cookie value (percent-encoded JSON string)
 * @returns {Object} Client ID to UID mapping
 */
function parseInteractionCookie(cookieValue) {
  if (!cookieValue) {
    return {};
  }

  /**
   * The mapping is stored percent-encoded, because raw JSON is not a valid RFC 6265
   * cookie-value and strict servers reject the whole request over it. Decoding is a
   * no-op for the two legacy formats (raw JSON and plain UID) since neither contains
   * a percent sign.
   */
  let raw = cookieValue;
  try {
    raw = decodeURIComponent(cookieValue);
  } catch {}

  try {
    const parsed = JSON.parse(raw);
    return isPlainObject(parsed) ? parsed : {};
  } catch {
    // If it's not JSON, treat as legacy single-value format
    return { _legacy: cookieValue };
  }
}

/**
 * Get the interaction UID for a specific client
 * @param {string|undefined} cookieValue - The raw cookie value
 * @param {string|null} clientId - The client ID
 * @returns {string|undefined} The interaction UID for this client
 */
export function getInteractionUid(cookieValue, clientId) {
  const mapping = parseInteractionCookie(cookieValue);
  return mapping[clientId] || mapping._legacy;
}

/**
 * Set the interaction UID for a specific client
 * @param {string|undefined} cookieValue - The current cookie value
 * @param {string|null} clientId - The client ID
 * @param {string} uid - The interaction UID
 * @returns {string} The new cookie value (percent-encoded JSON string)
 */
export function setInteractionUid(cookieValue, clientId, uid) {
  const mapping = parseInteractionCookie(cookieValue);

  /**
   * Delete before assigning so the entry moves to the end of the object: insertion order
   * survives JSON round-trips, so it doubles as least-recently-written order for eviction.
   * The exception — uint32-range numeric-string keys enumerate first regardless of insertion
   * order, carrying no recency information — cannot occur here, since client IDs are CIMD
   * URLs or 21-character nanoids, never uint32-range numeric strings.
   */
  delete mapping[clientId];
  mapping[clientId] = uid;
  // Also set the legacy key for backward compatibility
  mapping._legacy = uid;

  /**
   * Evict the least recently written client entries until the mapping fits the bounds; the
   * _legacy key and the just-written client are preferred survivors. The entry bound is
   * arithmetic, so it is settled before the size loop and each loop iteration re-encodes
   * only for the size bound.
   */
  const evictable = difference(Object.keys(mapping), ['_legacy', String(clientId)]);

  const overflow = Math.max(0, evictable.length + 1 - MAX_CLIENT_ENTRIES);
  for (const key of evictable.splice(0, overflow)) {
    delete mapping[key];
  }

  let encoded = encodeURIComponent(JSON.stringify(mapping));
  while (evictable.length && encoded.length > MAX_ENCODED_LENGTH) {
    delete mapping[evictable.shift()];
    encoded = encodeURIComponent(JSON.stringify(mapping));
  }

  /**
   * If the just-written entry alone exceeds the size bound, fall back to a legacy-only
   * mapping: the writing client still resolves through _legacy, whereas an over-limit value
   * would be rejected by the browser wholesale and break that client entirely.
   */
  if (encoded.length > MAX_ENCODED_LENGTH) {
    encoded = encodeURIComponent(JSON.stringify({ _legacy: uid }));
  }

  return encoded;
}
