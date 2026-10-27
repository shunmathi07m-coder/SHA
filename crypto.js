/**
 * Which One Did I Send? — Crypto Helper
 * Provides SHA-256 fingerprinting using browser Web Crypto API (SubtleCrypto)
 * and hash-chain computation for tamper-evident history.
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.FileGuardCrypto = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

  /**
   * Convert an ArrayBuffer or Uint8Array to a lowercase hex string
   */
  function bufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  /**
   * Calculate SHA-256 digest of an ArrayBuffer, Uint8Array, or string.
   * Works in browser (crypto.subtle) and Node.js (crypto module).
   */
  async function sha256Hex(data) {
    let arrayBuffer;
    if (typeof data === 'string') {
      const encoder = new TextEncoder();
      arrayBuffer = encoder.encode(data).buffer;
    } else if (data instanceof Uint8Array) {
      arrayBuffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength);
    } else if (data instanceof ArrayBuffer) {
      arrayBuffer = data;
    } else if (typeof Blob !== 'undefined' && data instanceof Blob) {
      arrayBuffer = await data.arrayBuffer();
    } else {
      throw new TypeError('Unsupported data type for SHA-256 calculation');
    }

    // Web Crypto API in browser / worker
    if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.digest === 'function') {
      const hashBuffer = await crypto.subtle.digest('SHA-256', arrayBuffer);
      return bufferToHex(hashBuffer);
    }

    // Node.js fallback for unit tests
    if (typeof require === 'function') {
      try {
        const nodeCrypto = require('crypto');
        return nodeCrypto.createHash('sha256').update(Buffer.from(arrayBuffer)).digest('hex');
      } catch (e) {
        // Fallback below
      }
    }

    throw new Error('No cryptographic SHA-256 implementation available in current environment');
  }

  /**
   * Canonical JSON serializer to guarantee deterministic key ordering for hashing
   */
  function canonicalStringify(obj) {
    if (obj === null || typeof obj !== 'object') {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return '[' + obj.map(canonicalStringify).join(',') + ']';
    }
    const keys = Object.keys(obj).sort();
    const parts = keys.map(k => JSON.stringify(k) + ':' + canonicalStringify(obj[k]));
    return '{' + parts.join(',') + '}';
  }

  /**
   * Computes the tamper-evident hash for a history record.
   * recordHash = SHA-256(prevHash + "::" + canonicalJson(cleanRecordData))
   */
  async function computeRecordHash(prevHash, recordData) {
    // Clone and strip volatile/derived hash fields if present
    const cleanData = Object.assign({}, recordData);
    delete cleanData.recordHash;
    delete cleanData.prevHash;

    const payload = (prevHash || GENESIS_PREV_HASH) + '::' + canonicalStringify(cleanData);
    return await sha256Hex(payload);
  }

  /**
   * Abbreviates a hash for UI display (e.g. 7f83b165...4b92)
   */
  function formatShortHash(hash, head = 8, tail = 6) {
    if (!hash || hash.length <= head + tail) return hash || '';
    return hash.slice(0, head) + '...' + hash.slice(-tail);
  }

  return {
    GENESIS_PREV_HASH,
    sha256Hex,
    computeRecordHash,
    canonicalStringify,
    formatShortHash
  };
});
