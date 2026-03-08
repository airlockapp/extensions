// lib/canonical-json.mjs
// RFC 8785 JSON Canonicalization Scheme (JCS)
// Mirrors Harp.Common/CanonicalJson.cs

import canonicalize from 'canonicalize';

/**
 * Remove all keys whose value is null or undefined.
 * Mirrors C#'s JsonIgnoreCondition.WhenWritingNull
 */
function stripNulls(obj) {
    return JSON.parse(JSON.stringify(obj, (_k, v) => (v === null || v === undefined ? undefined : v)));
}

/**
 * Canonicalize an object to a JCS string, stripping nulls.
 * @param {object} obj
 * @returns {string}
 */
export function jcsCanonicalize(obj) {
    return canonicalize(stripNulls(obj));
}

/**
 * Canonicalize an object to JCS UTF-8 bytes, stripping nulls.
 * @param {object} obj
 * @returns {Buffer}
 */
export function jcsCanonicalizeUtf8(obj) {
    return Buffer.from(jcsCanonicalize(obj), 'utf8');
}
