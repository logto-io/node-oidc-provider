/**
 * LOGTO PATCH(client-specific-interaction-uid)
 *
 * Helper functions to manage client-specific interaction UIDs in a single cookie
 */

import isPlainObject from './_/is_plain_object.js';

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

  // Add the new mapping
  mapping[clientId] = uid;
  // Also set the legacy key for backward compatibility
  mapping._legacy = uid;

  return encodeURIComponent(JSON.stringify(mapping));
}
