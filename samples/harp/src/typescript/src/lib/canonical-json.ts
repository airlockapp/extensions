/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 * Mirrors Harp.Common/CanonicalJson.cs.
 */

import canonicalize from "canonicalize";

/** Remove all keys whose value is null or undefined. */
function stripNulls(obj: unknown): unknown {
    if (obj === null || obj === undefined) return undefined;
    if (Array.isArray(obj)) return obj.map(stripNulls);
    if (typeof obj === "object") {
        const result: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
            if (value !== null && value !== undefined) {
                result[key] = stripNulls(value);
            }
        }
        return result;
    }
    return obj;
}

/** Canonicalize an object to a JCS string, stripping nulls. */
export function jcsCanonicalize(obj: unknown): string {
    const result = canonicalize(stripNulls(obj));
    if (result === undefined) {
        throw new Error("Canonicalization returned undefined");
    }
    return result;
}

/** Canonicalize an object to JCS UTF-8 bytes, stripping nulls. */
export function jcsCanonicalizeUtf8(obj: unknown): Buffer {
    return Buffer.from(jcsCanonicalize(obj), "utf8");
}
