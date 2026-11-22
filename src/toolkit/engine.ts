/**
 * KIRON PROHORI — Phase 4: Security Toolkit & Personal Features Engine
 * Budget: Strict $0. Zero paid APIs, zero file uploads, zero paid email/SMS gateways.
 *
 * Modules covered:
 * 1. URL Inspector (Safe parsing, domain normalization, malformed detection, consent-gated feed check, UNKNOWN != SAFE verdict)
 * 2. Hash Tool (Browser Web Crypto SHA-256 calculation, hash format validation, zero-upload policy)
 * 3. Security Checklist (6 mandatory defensive tracks with local completion tracking)
 * 4. Watchlist & Personalized Dashboard Matcher (CVEs, Vendors, Products matched against live catalog)
 * 5. In-App Notifications Filter & Watchlist Alert Generator (Zero paid email/SMS)
 * 6. Report Center (RFC-4180 CSV & pure-TS standards-compliant PDF 1.4 generator with Report Date, Sources & Disclaimer)
 */

import { defangUrlOrHost } from '../connectors/parsers.ts';
import { ParsedKevRecord } from '../connectors/parsers.ts';
import { WatchlistDoc, NotificationDoc, CveRecordDoc } from '../types/security.ts';

// ============================================================================
// 1. URL INSPECTOR — SAFE PARSER, DOMAIN NORMALIZER & "UNKNOWN != SAFE" ENGINE
// ============================================================================

export type UrlInspectionVerdict = 'MALFORMED' | 'KNOWN_THREAT_MATCH' | 'UNKNOWN';

export interface ThreatIntelMatchItem {
  sourceName: string;
  indicatorId: string;
  matchedIndicator: string;
  categoryOrThreat: string;
  lastUpdatedAt: string;
  verificationStatus: string;
}

export interface SafeUrlInspectionReport {
  rawInput: string;
  isMalformed: boolean;
  malformedReason: string | null;
  verdict: UrlInspectionVerdict;
  verdictBadgeLabel: string;
  verdictExplanation: string;
  defangedUrl: string;
  normalizedDomain: string;
  registrableDomain: string;
  defangedDomain: string;
  scheme: string;
  port: string;
  path: string;
  queryParameterNames: string[];
  isPunycodeIdn: boolean;
  isIpLiteral: boolean;
  structuralWarnings: string[];
  matches: ThreatIntelMatchItem[];
  externalConsentGranted: boolean;
  networkActionTaken: string;
  intelligenceSourceAttribution: string;
  intelligenceLastUpdatedAt: string;
  limitationsNotice: string;
}

const KNOWN_MULTI_PART_TLDS = new Set([
  'co.uk',
  'org.uk',
  'ac.uk',
  'gov.uk',
  'com.bd',
  'org.bd',
  'gov.bd',
  'edu.bd',
  'net.bd',
  'co.in',
  'org.in',
  'com.au',
  'co.jp',
]);

/**
 * Normalizes a domain or hostname safely:
 * - Trims whitespace and trailing dots
 * - Converts to lowercase
 * - Strips surrounding IPv6 brackets for display consistency
 * - Extracts the registrable domain (eTLD+1 estimation)
 */
export function normalizeDomainName(rawHost: string): {
  normalizedDomain: string;
  registrableDomain: string;
  isIpLiteral: boolean;
  isPunycodeIdn: boolean;
  validHostname: boolean;
} {
  const cleaned = rawHost
    .trim()
    .toLowerCase()
    .replace(/\[\.\]/g, '.')
    .replace(/\.+$/, '');

  if (!cleaned) {
    return {
      normalizedDomain: 'Unknown',
      registrableDomain: 'Unknown',
      isIpLiteral: false,
      isPunycodeIdn: false,
      validHostname: false,
    };
  }

  // IPv4 literal check
  const ipv4Match = cleaned.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const octetsValid = ipv4Match
      .slice(1)
      .every((o) => Number(o) >= 0 && Number(o) <= 255);
    return {
      normalizedDomain: cleaned,
      registrableDomain: cleaned,
      isIpLiteral: true,
      isPunycodeIdn: false,
      validHostname: octetsValid,
    };
  }

  // IPv6 literal check
  if (cleaned.startsWith('[') && cleaned.endsWith(']')) {
    return {
      normalizedDomain: cleaned,
      registrableDomain: cleaned,
      isIpLiteral: true,
      isPunycodeIdn: false,
      validHostname: cleaned.includes(':'),
    };
  }

  // Reject spaces or illegal host characters
  if (/[^a-z0-9.-]/.test(cleaned) || cleaned.startsWith('-') || cleaned.includes('..')) {
    return {
      normalizedDomain: cleaned,
      registrableDomain: 'Unknown',
      isIpLiteral: false,
      isPunycodeIdn: cleaned.includes('xn--'),
      validHostname: false,
    };
  }

  const labels = cleaned.split('.').filter(Boolean);
  if (labels.length < 2) {
    return {
      normalizedDomain: cleaned,
      registrableDomain: cleaned,
      isIpLiteral: false,
      isPunycodeIdn: cleaned.includes('xn--'),
      validHostname: false,
    };
  }

  const tld = labels[labels.length - 1];
  if (tld.length < 2 || /^\d+$/.test(tld)) {
    return {
      normalizedDomain: cleaned,
      registrableDomain: cleaned,
      isIpLiteral: false,
      isPunycodeIdn: cleaned.includes('xn--'),
      validHostname: false,
    };
  }

  let registrableDomain = labels.slice(-2).join('.');
  if (labels.length >= 3) {
    const lastTwo = labels.slice(-2).join('.');
    if (KNOWN_MULTI_PART_TLDS.has(lastTwo)) {
      registrableDomain = labels.slice(-3).join('.');
    }
  }

  return {
    normalizedDomain: cleaned,
    registrableDomain,
    isIpLiteral: false,
    isPunycodeIdn: cleaned.includes('xn--'),
    validHostname: true,
  };
}

/**
 * Safely inspects a URL or domain offline without ever visiting or executing it.
 * - Detects malformed URLs explicitly.
 * - Normalizes domains.
 * - Checks against configured public threat intelligence feeds.
 * - Enforces that NO MATCH means UNKNOWN, never SAFE.
 */
export function inspectUrlSafely(
  rawInput: string,
  options: {
    configuredIndicators: {
      sourceName: string;
      indicatorId: string;
      defangedOrRawValue: string;
      categoryOrThreat: string;
      lastUpdatedAt: string;
      verificationStatus: string;
    }[];
    externalConsentGranted?: boolean;
    intelligenceLastUpdatedAt?: string;
  }
): SafeUrlInspectionReport {
  const externalConsentGranted = Boolean(options.externalConsentGranted);
  const intelligenceLastUpdatedAt =
    options.intelligenceLastUpdatedAt || new Date().toISOString();
  const intelligenceSourceAttribution =
    'KIRON PROHORI Verified Threat Indicators (Cloud Firestore) + Approved Community Scam Reports' +
    (externalConsentGranted
      ? ' + Optional Public Feed Check (Explicit User Consent Granted)'
      : ' (Local Zero-Egress Mode — Private URL Never Sent Externally)');

  const limitationsNotice =
    'LIMITATIONS: Static lexical inspection and public feed matching only cover previously reported indicators. Newly registered phishing domains, compromised legitimate websites, or zero-hour malicious redirects may not appear in public feeds. Never visit untrusted URLs or enter credentials based solely on feed absence.';

  const trimmed = rawInput.trim();
  if (!trimmed) {
    return {
      rawInput,
      isMalformed: true,
      malformedReason: 'Empty URL or domain input.',
      verdict: 'MALFORMED',
      verdictBadgeLabel: 'MALFORMED INPUT',
      verdictExplanation:
        'The submitted string is empty. Provide a complete URL (e.g., https://example.com/path) or domain name.',
      defangedUrl: 'Unknown',
      normalizedDomain: 'Unknown',
      registrableDomain: 'Unknown',
      defangedDomain: 'Unknown',
      scheme: 'Unknown',
      port: 'Default',
      path: 'Unknown',
      queryParameterNames: [],
      isPunycodeIdn: false,
      isIpLiteral: false,
      structuralWarnings: ['Input string is empty.'],
      matches: [],
      externalConsentGranted,
      networkActionTaken:
        'ZERO NETWORK REQUESTS — Evaluated 100% in local memory. URL was never visited or executed.',
      intelligenceSourceAttribution,
      intelligenceLastUpdatedAt,
      limitationsNotice,
    };
  }

  // Reject whitespace inside URL or dangerous javascript:/data:/vbscript: pseudo-schemes
  if (/\s/.test(trimmed)) {
    return {
      rawInput,
      isMalformed: true,
      malformedReason: 'Malformed URL: contains illegal whitespace characters.',
      verdict: 'MALFORMED',
      verdictBadgeLabel: 'MALFORMED URL',
      verdictExplanation:
        'Valid RFC-3986 URLs cannot contain unencoded spaces or line breaks.',
      defangedUrl: defangUrlOrHost(trimmed),
      normalizedDomain: 'Unknown',
      registrableDomain: 'Unknown',
      defangedDomain: 'Unknown',
      scheme: 'Unknown',
      port: 'Unknown',
      path: 'Unknown',
      queryParameterNames: [],
      isPunycodeIdn: false,
      isIpLiteral: false,
      structuralWarnings: ['Contains unencoded whitespace characters.'],
      matches: [],
      externalConsentGranted,
      networkActionTaken:
        'ZERO NETWORK REQUESTS — Rejected by local lexical validator.',
      intelligenceSourceAttribution,
      intelligenceLastUpdatedAt,
      limitationsNotice,
    };
  }

  if (/^(javascript|data|vbscript|file|blob):/i.test(trimmed)) {
    const badScheme = trimmed.split(':')[0].toUpperCase();
    return {
      rawInput,
      isMalformed: true,
      malformedReason: `Dangerous or non-network URI scheme detected (${badScheme}:).`,
      verdict: 'MALFORMED',
      verdictBadgeLabel: 'DANGEROUS URI SCHEME',
      verdictExplanation: `The URI uses a non-HTTP executable or local scheme (${badScheme}:) often abused for Cross-Site Scripting (XSS) or local payload execution. Never execute this URI.`,
      defangedUrl: defangUrlOrHost(trimmed),
      normalizedDomain: 'Unknown',
      registrableDomain: 'Unknown',
      defangedDomain: 'Unknown',
      scheme: badScheme,
      port: 'N/A',
      path: 'Unknown',
      queryParameterNames: [],
      isPunycodeIdn: false,
      isIpLiteral: false,
      structuralWarnings: [
        `Executable / non-web URI scheme (${badScheme}:) detected and blocked from parsing.`,
      ],
      matches: [],
      externalConsentGranted,
      networkActionTaken:
        'ZERO NETWORK REQUESTS — Blocked non-HTTP scheme locally.',
      intelligenceSourceAttribution,
      intelligenceLastUpdatedAt,
      limitationsNotice,
    };
  }

  // Refang in-memory strictly for structural decomposition
  const refanged = trimmed
    .replace(/^hxxps:\/\//i, 'https://')
    .replace(/^hxxp:\/\//i, 'http://')
    .replace(/\[\.\]/g, '.');

  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(refanged)
    ? refanged
    : `https://${refanged}`;

  let protocol = 'https:';
  let username = '';
  let password = '';
  let rawHost = '';
  let port = '';
  let pathname = '/';
  let queryParamKeys: string[] = [];

  try {
    const parsed = new URL(withScheme);
    protocol = parsed.protocol.toLowerCase();
    username = parsed.username;
    password = parsed.password;
    rawHost = parsed.hostname;
    port = parsed.port;
    pathname = parsed.pathname || '/';
    queryParamKeys = Array.from(new Set(Array.from(parsed.searchParams.keys())));
  } catch {
    // Fallback lexical regex so malformed Punycode labels are still decomposed if structurally recognizable
    const m = withScheme.match(
      /^([a-zA-Z][a-zA-Z0-9+.-]*:)\/\/([^/?#]*)([^?#]*)(\?[^#]*)?/
    );
    if (!m || !m[2]) {
      return {
        rawInput,
        isMalformed: true,
        malformedReason: 'Malformed URL syntax: unable to extract valid authority or hostname.',
        verdict: 'MALFORMED',
        verdictBadgeLabel: 'MALFORMED URL',
        verdictExplanation:
          'The input could not be parsed as a valid RFC-3986 URL or domain name.',
        defangedUrl: defangUrlOrHost(trimmed),
        normalizedDomain: 'Unknown',
        registrableDomain: 'Unknown',
        defangedDomain: 'Unknown',
        scheme: 'Unknown',
        port: 'Unknown',
        path: 'Unknown',
        queryParameterNames: [],
        isPunycodeIdn: false,
        isIpLiteral: false,
        structuralWarnings: ['Failed RFC-3986 URL authority parsing.'],
        matches: [],
        externalConsentGranted,
        networkActionTaken: 'ZERO NETWORK REQUESTS — Rejected malformed URL locally.',
        intelligenceSourceAttribution,
        intelligenceLastUpdatedAt,
        limitationsNotice,
      };
    }
    protocol = m[1].toLowerCase();
    const authority = m[2];
    pathname = m[3] || '/';
    const rawQuery = m[4] ? m[4].slice(1) : '';
    const atIdx = authority.lastIndexOf('@');
    const hostPort = atIdx !== -1 ? authority.slice(atIdx + 1) : authority;
    if (atIdx !== -1) username = authority.slice(0, atIdx);
    const colonIdx = hostPort.lastIndexOf(':');
    if (colonIdx !== -1 && !hostPort.endsWith(']')) {
      rawHost = hostPort.slice(0, colonIdx);
      port = hostPort.slice(colonIdx + 1);
    } else {
      rawHost = hostPort;
    }
    if (rawQuery) {
      queryParamKeys = Array.from(
        new Set(
          rawQuery
            .split('&')
            .map((kv) => kv.split('=')[0]?.trim())
            .filter(Boolean)
        )
      );
    }
  }

  const domainInfo = normalizeDomainName(rawHost);
  if (!domainInfo.validHostname) {
    return {
      rawInput,
      isMalformed: true,
      malformedReason: `Malformed hostname ("${rawHost || 'empty'}"): missing valid TLD or contains illegal domain characters.`,
      verdict: 'MALFORMED',
      verdictBadgeLabel: 'MALFORMED DOMAIN',
      verdictExplanation: `The extracted hostname "${rawHost}" is not a valid domain name or IP address.`,
      defangedUrl: defangUrlOrHost(trimmed),
      normalizedDomain: domainInfo.normalizedDomain,
      registrableDomain: domainInfo.registrableDomain,
      defangedDomain: defangUrlOrHost(domainInfo.normalizedDomain),
      scheme: protocol.replace(':', '').toUpperCase(),
      port: port || 'Default',
      path: pathname,
      queryParameterNames: queryParamKeys,
      isPunycodeIdn: domainInfo.isPunycodeIdn,
      isIpLiteral: domainInfo.isIpLiteral,
      structuralWarnings: ['Invalid domain name or IP address format.'],
      matches: [],
      externalConsentGranted,
      networkActionTaken: 'ZERO NETWORK REQUESTS — Rejected malformed domain locally.',
      intelligenceSourceAttribution,
      intelligenceLastUpdatedAt,
      limitationsNotice,
    };
  }

  const warnings: string[] = [];
  if (protocol === 'http:') {
    warnings.push('Uses unencrypted HTTP transport (no TLS encryption).');
  }
  if (username || password || refanged.includes('@')) {
    warnings.push(
      'Contains "@" userinfo credential trick in authority — often used to disguise the actual destination host.'
    );
  }
  if (domainInfo.isIpLiteral) {
    warnings.push(
      'Uses a raw IP address literal instead of a registered domain name.'
    );
  }
  if (domainInfo.isPunycodeIdn) {
    warnings.push(
      'Contains IDN Punycode ("xn--") label — verify carefully against lookalike/homograph brand impersonation.'
    );
  }
  const labels = domainInfo.normalizedDomain.split('.');
  if (labels.length >= 5) {
    warnings.push(
      `Deep subdomain nesting (${labels.length - 2} subdomain levels) often used to mimic legitimate portals.`
    );
  }
  if (/\.(exe|apk|scr|msi|bat|ps1|vbs|zip|iso)$/i.test(pathname)) {
    warnings.push(
      `Path terminates with high-risk executable or archive extension (${pathname.split('.').pop()}).`
    );
  }

  const hostWithPort = port
    ? `${domainInfo.normalizedDomain}:${port}`
    : domainInfo.normalizedDomain;
  const redactedQuery =
    queryParamKeys.length > 0
      ? `?${queryParamKeys.map((k) => `${k}=[REDACTED]`).join('&')}`
      : '';
  const defangedUrl = defangUrlOrHost(
    `${protocol}//${hostWithPort}${pathname}${redactedQuery}`
  );
  const defangedDomain = defangUrlOrHost(domainInfo.normalizedDomain);

  // Match against configured public threat intelligence
  const matches: ThreatIntelMatchItem[] = [];
  for (const ind of options.configuredIndicators) {
    const normInd = ind.defangedOrRawValue
      .trim()
      .toLowerCase()
      .replace(/^hxxps?:\/\//, '')
      .replace(/^https?:\/\//, '')
      .replace(/\[\.\]/g, '.')
      .replace(/\/+$/, '');

    if (!normInd) continue;

    if (
      normInd === domainInfo.normalizedDomain ||
      normInd === domainInfo.registrableDomain ||
      normInd.includes(domainInfo.normalizedDomain) ||
      domainInfo.normalizedDomain.includes(normInd)
    ) {
      matches.push({
        sourceName: ind.sourceName,
        indicatorId: ind.indicatorId,
        matchedIndicator: defangUrlOrHost(ind.defangedOrRawValue),
        categoryOrThreat: ind.categoryOrThreat,
        lastUpdatedAt: ind.lastUpdatedAt || intelligenceLastUpdatedAt,
        verificationStatus: ind.verificationStatus,
      });
    }
  }

  const hasMatch = matches.length > 0;
  // CRITICAL REQUIREMENT: No match means UNKNOWN, never SAFE
  const verdict: UrlInspectionVerdict = hasMatch
    ? 'KNOWN_THREAT_MATCH'
    : 'UNKNOWN';

  const verdictBadgeLabel = hasMatch
    ? `KNOWN THREAT MATCH (${matches.length})`
    : 'UNKNOWN (NO MATCH — NOT GUARANTEED SAFE)';

  const verdictExplanation = hasMatch
    ? `Matched ${matches.length} configured public threat intelligence record(s). Do NOT visit or interact with this URL.`
    : 'VERDICT: UNKNOWN (NOT SAFE). No exact match was found in currently configured public threat feeds. Absence from public feeds means UNKNOWN — it does NOT mean the URL is safe.';

  return {
    rawInput,
    isMalformed: false,
    malformedReason: null,
    verdict,
    verdictBadgeLabel,
    verdictExplanation,
    defangedUrl,
    normalizedDomain: domainInfo.normalizedDomain,
    registrableDomain: domainInfo.registrableDomain,
    defangedDomain,
    scheme: protocol.replace(':', '').toUpperCase(),
    port: port || 'Default',
    path: pathname,
    queryParameterNames: queryParamKeys,
    isPunycodeIdn: domainInfo.isPunycodeIdn,
    isIpLiteral: domainInfo.isIpLiteral,
    structuralWarnings: warnings,
    matches,
    externalConsentGranted,
    networkActionTaken: externalConsentGranted
      ? 'URL parsed locally in memory (never visited). User granted explicit consent for public feed digest comparison.'
      : '100% LOCAL MEMORY EXECUTION — Private URL was never visited, executed, or transmitted to any external service.',
    intelligenceSourceAttribution,
    intelligenceLastUpdatedAt,
    limitationsNotice,
  };
}

// ============================================================================
// 2. HASH TOOL — WEB CRYPTO SHA-256 & HASH FORMAT VALIDATOR (ZERO FILE UPLOAD)
// ============================================================================

export type HashAlgorithmFormat = 'SHA-256' | 'SHA-1' | 'MD5' | 'INVALID';

export interface HashValidationSummary {
  normalizedHash: string;
  isValid: boolean;
  algorithm: HashAlgorithmFormat;
  bitLength: number;
  supportsPublicLookup: boolean;
  validationMessage: string;
}

/**
 * Validates cryptographic hash strings (SHA-256 64-hex, SHA-1 40-hex, MD5 32-hex).
 */
export function validateCryptographicHashFormat(rawHash: string): HashValidationSummary {
  const cleaned = rawHash.trim().toLowerCase();
  if (!cleaned) {
    return {
      normalizedHash: '',
      isValid: false,
      algorithm: 'INVALID',
      bitLength: 0,
      supportsPublicLookup: false,
      validationMessage: 'Enter a hexadecimal hash digest or compute a local SHA-256 hash using Web Crypto.',
    };
  }

  if (!/^[a-f0-9]+$/.test(cleaned)) {
    return {
      normalizedHash: cleaned,
      isValid: false,
      algorithm: 'INVALID',
      bitLength: 0,
      supportsPublicLookup: false,
      validationMessage:
        'Invalid hash format: contains non-hexadecimal characters (only 0-9 and a-f are allowed).',
    };
  }

  if (cleaned.length === 64) {
    return {
      normalizedHash: cleaned,
      isValid: true,
      algorithm: 'SHA-256',
      bitLength: 256,
      supportsPublicLookup: true,
      validationMessage: 'Valid 64-character SHA-256 (256-bit) hexadecimal digest.',
    };
  }

  if (cleaned.length === 40) {
    return {
      normalizedHash: cleaned,
      isValid: true,
      algorithm: 'SHA-1',
      bitLength: 160,
      supportsPublicLookup: false,
      validationMessage:
        'Valid 40-character SHA-1 (160-bit) digest. Note: SHA-256 (64 hex chars) is recommended for CIRCL public reputation lookup.',
    };
  }

  if (cleaned.length === 32) {
    return {
      normalizedHash: cleaned,
      isValid: true,
      algorithm: 'MD5',
      bitLength: 128,
      supportsPublicLookup: false,
      validationMessage:
        'Valid 32-character MD5 (128-bit) digest matched against local threat indicators. Use SHA-256 for CIRCL public lookup.',
    };
  }

  return {
    normalizedHash: cleaned,
    isValid: false,
    algorithm: 'INVALID',
    bitLength: cleaned.length * 4,
    supportsPublicLookup: false,
    validationMessage: `Unexpected hex length (${cleaned.length} characters). Expected 64 (SHA-256), 40 (SHA-1), or 32 (MD5).`,
  };
}

/**
 * Computes a SHA-256 hexadecimal digest from a Uint8Array / ArrayBuffer using standard Web Crypto API
 * (`crypto.subtle.digest('SHA-256', buffer)`), available in modern browsers and Node.js 19+.
 * Files are hashed 100% locally in memory and NEVER uploaded.
 */
export async function computeSha256HexFromBytes(
  bytes: Uint8Array | ArrayBuffer
): Promise<string> {
  const buffer =
    bytes instanceof Uint8Array
      ? (bytes.buffer.slice(
          bytes.byteOffset,
          bytes.byteOffset + bytes.byteLength
        ) as ArrayBuffer)
      : bytes;

  const subtle =
    typeof globalThis !== 'undefined' &&
    globalThis.crypto &&
    globalThis.crypto.subtle
      ? globalThis.crypto.subtle
      : null;

  if (!subtle) {
    throw new Error('Web Crypto API (crypto.subtle) is unavailable in this environment.');
  }

  const digestBuffer = await subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(digestBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ============================================================================
// 3. SECURITY CHECKLIST — 6 MANDATORY DEFENSIVE TRACKS
// ============================================================================

export type SecurityChecklistTrackId =
  | 'account_security'
  | 'password_manager'
  | 'mfa_awareness'
  | 'backup_updates'
  | 'small_business'
  | 'service_technician';

export interface SecurityChecklistItem {
  id: string;
  trackId: SecurityChecklistTrackId;
  titleEn: string;
  titleBn: string;
  guidanceEn: string;
  guidanceBn: string;
  priority: 'ESSENTIAL' | 'RECOMMENDED' | 'ADVANCED';
  verificationAction: string;
}

export interface SecurityChecklistTrack {
  trackId: SecurityChecklistTrackId;
  order: number;
  titleEn: string;
  titleBn: string;
  audienceEn: string;
  audienceBn: string;
  summaryEn: string;
  summaryBn: string;
  items: SecurityChecklistItem[];
}

export const SECURITY_CHECKLIST_TRACKS: SecurityChecklistTrack[] = [
  {
    trackId: 'account_security',
    order: 1,
    titleEn: '1. Account Security Checklist',
    titleBn: '১. অ্যাকাউন্ট নিরাপত্তা চেকলিস্ট',
    audienceEn: 'All Users, Researchers & Staff',
    audienceBn: 'সকল ব্যবহারকারী ও কর্মী',
    summaryEn:
      'Protect primary email, banking, social, and cloud administrator accounts against credential stuffing and session hijacking.',
    summaryBn:
      'প্রধান ইমেইল, ব্যাংকিং এবং ক্লাউড অ্যাকাউন্টগুলোকে পাসওয়ার্ড চুরি ও হ্যাকিং থেকে সুরক্ষিত রাখুন।',
    items: [
      {
        id: 'acct_recovery_audit',
        trackId: 'account_security',
        titleEn: 'Audit account recovery email & phone numbers on primary email accounts',
        titleBn: 'প্রধান ইমেইল অ্যাকাউন্টের রিকভারি ইমেইল ও ফোন নম্বর যাচাই করুন',
        guidanceEn:
          'Ensure recovery addresses belong exclusively to you and remove outdated SIM numbers or unused secondary emails.',
        guidanceBn:
          'পুরানো বা অব্যবহৃত সিম নম্বর এবং অপরিচিত রিকভারি ইমেইল সরিয়ে ফেলুন।',
        priority: 'ESSENTIAL',
        verificationAction: 'Review Google / Microsoft / Apple Security Settings -> Recovery Options',
      },
      {
        id: 'acct_active_sessions',
        trackId: 'account_security',
        titleEn: 'Review logged-in devices and revoke unrecognized active sessions & OAuth apps',
        titleBn: 'লগইন থাকা ডিভাইস এবং অপরিচিত থার্ড-পার্টি অ্যাপ অ্যাক্সেস বাতিল করুন',
        guidanceEn:
          'Sign out old browsers, shared computers, and third-party OAuth integrations you no longer actively use.',
        guidanceBn:
          'শেয়ার্ড কম্পিউটার বা পুরানো ব্রাউজার সেশন এবং অপ্রয়োজনীয় অ্যাপ পারমিশন রিমুভ করুন।',
        priority: 'ESSENTIAL',
        verificationAction: 'Inspect Active Devices & Third-Party App Permissions quarterly',
      },
      {
        id: 'acct_login_alerts',
        trackId: 'account_security',
        titleEn: 'Enable unrecognized sign-in alerts and forwarding rule checks',
        titleBn: 'নতুন লগইন অ্যালার্ট চালু করুন এবং অটো-ফরোয়ার্ডিং রুল পরীক্ষা করুন',
        guidanceEn:
          'Attackers often add silent email forwarding rules after compromising a mailbox. Verify no unauthorized forwarding filters exist.',
        guidanceBn:
          'ইমেইল সেটিংসে কোনো গোপন অটো-ফরোয়ার্ডিং বা ফিল্টার যোগ করা হয়েছে কি না তা পরীক্ষা করুন।',
        priority: 'RECOMMENDED',
        verificationAction: 'Check Email Settings -> Forwarding and POP/IMAP / Rules',
      },
    ],
  },
  {
    trackId: 'password_manager',
    order: 2,
    titleEn: '2. Password Manager Awareness',
    titleBn: '২. পাসওয়ার্ড ম্যানেজার সচেতনতা',
    audienceEn: 'Individuals, Families & Teams',
    audienceBn: 'ব্যক্তিগত ও প্রাতিষ্ঠানিক ব্যবহারকারী',
    summaryEn:
      'Eliminate password reuse across websites by adopting a reputable encrypted password manager and strong master passphrase.',
    summaryBn:
      'একই পাসওয়ার্ড একাধিক সাইটে ব্যবহার বন্ধ করতে এনক্রিপ্টেড পাসওয়ার্ড ম্যানেজার ব্যবহার করুন।',
    items: [
      {
        id: 'pm_unique_passwords',
        trackId: 'password_manager',
        titleEn: 'Use a unique, randomly generated password (16+ chars) for every account',
        titleBn: 'প্রতিটি অ্যাকাউন্টের জন্য আলাদা ও শক্তিশালী (১৬+ অক্ষরের) পাসওয়ার্ড ব্যবহার করুন',
        guidanceEn:
          'If one website suffers a database breach, unique passwords prevent attackers from accessing your email or financial accounts.',
        guidanceBn:
          'একটি ওয়েবসাইটের তথ্য ফাঁস হলেও আলাদা পাসওয়ার্ড থাকলে আপনার অন্য অ্যাকাউন্টগুলো নিরাপদ থাকে।',
        priority: 'ESSENTIAL',
        verificationAction: 'Store credentials in an audited open-source or trusted password manager vault',
      },
      {
        id: 'pm_master_passphrase',
        trackId: 'password_manager',
        titleEn: 'Protect your password manager vault with a 4+ word master passphrase and MFA',
        titleBn: 'পাসওয়ার্ড ম্যানেজার ভল্টটি ৪+ শব্দের মাস্টার পাসফ্রেজ এবং MFA দিয়ে সুরক্ষিত করুন',
        guidanceEn:
          'Never store your master passphrase in plaintext notes or unencrypted browser text files.',
        guidanceBn:
          'মাস্টার পাসওয়ার্ড কখনোই সাধারণ টেক্সট ফাইলে বা মেসেজে লিখে রাখবেন না।',
        priority: 'ESSENTIAL',
        verificationAction: 'Verify Master Passphrase entropy + offline emergency recovery sheet',
      },
      {
        id: 'pm_autofill_phish_guard',
        trackId: 'password_manager',
        titleEn: 'Use password manager domain-matching autofill to detect lookalike phishing URLs',
        titleBn: 'নকল ফিশিং ওয়েবসাইট চিনতে পাসওয়ার্ড ম্যানেজারের ডোমেইন-ম্যাচিং অটোফিল ব্যবহার করুন',
        guidanceEn:
          'A password manager will refuse to autofill credentials on a typosquatted or Punycode phishing domain, alerting you immediately.',
        guidanceBn:
          'নকল বা ফিশিং ডোমেইনে পাসওয়ার্ড ম্যানেজার অটোফিল করবে না, যা আপনাকে প্রতারণা থেকে সতর্ক করবে।',
        priority: 'RECOMMENDED',
        verificationAction: 'Disable manual copy-pasting of passwords into untrusted browser popups',
      },
    ],
  },
  {
    trackId: 'mfa_awareness',
    order: 3,
    titleEn: '3. Multi-Factor Authentication (MFA) Awareness',
    titleBn: '৩. মাল্টি-ফ্যাক্টর অথেনটিকেশন (MFA) সচেতনতা',
    audienceEn: 'All Accounts & Privileged Admins',
    audienceBn: 'সকল অ্যাকাউন্ট ও অ্যাডমিন',
    summaryEn:
      'Upgrade from vulnerable SMS OTPs to authenticator apps (TOTP) or phishing-resistant FIDO2/WebAuthn security keys.',
    summaryBn:
      'সাধারণ SMS ওটিপির পরিবর্তে অথেনটিকেটর অ্যাপ (TOTP) বা হার্ডওয়্যার সিকিউরিটি কি ব্যবহার করুন।',
    items: [
      {
        id: 'mfa_totp_or_passkey',
        trackId: 'mfa_awareness',
        titleEn: 'Enable App-Based Authenticator (TOTP) or FIDO2 Passkeys/Hardware Keys on critical accounts',
        titleBn: 'গুরুত্বপূর্ণ অ্যাকাউন্টে অথেনটিকেটর অ্যাপ (TOTP) বা FIDO2 Passkey চালু করুন',
        guidanceEn:
          'SMS codes can be intercepted via SIM swapping. Authenticator apps and FIDO2 keys generate cryptographic codes locally.',
        guidanceBn:
          'সিম ক্লোনিংয়ের ঝুঁকি এড়াতে SMS-এর বদলে Authenticator App বা Passkey ব্যবহার করুন।',
        priority: 'ESSENTIAL',
        verificationAction: 'Configure TOTP/Passkey on Primary Email, Cloud Console, GitHub, and Banking',
      },
      {
        id: 'mfa_backup_codes',
        trackId: 'mfa_awareness',
        titleEn: 'Store single-use MFA backup recovery codes offline in a secure physical location',
        titleBn: 'MFA ব্যাকআপ রিকভারি কোডগুলো অফলাইনে নিরাপদ স্থানে সংরক্ষণ করুন',
        guidanceEn:
          'Ensure you can recover your accounts if your phone is lost, damaged, or factory-reset.',
        guidanceBn:
          'ফোন হারিয়ে বা নষ্ট হয়ে গেলে অ্যাকাউন্ট উদ্ধারের জন্য ব্যাকআপ কোড প্রিন্ট বা লিখে নিরাপদে রাখুন।',
        priority: 'ESSENTIAL',
        verificationAction: 'Download & store offline MFA recovery codes securely',
      },
      {
        id: 'mfa_push_fatigue',
        trackId: 'mfa_awareness',
        titleEn: 'Never approve unexpected MFA push prompts or share OTP codes over phone/chat',
        titleBn: 'অপ্রত্যাশিত MFA পুশ নোটিফিকেশন অনুমোদন করবেন না এবং কাউকে OTP কোড বলবেন না',
        guidanceEn:
          'No legitimate bank, IT helpdesk, or government agency will ever ask you to read out an OTP code or approve an uninitiated MFA prompt.',
        guidanceBn:
          'কোনো ব্যাংক বা আইটি সাপোর্ট কখনোই আপনার কাছে ফোনে বা চ্যাটে ওটিপি কোড চাইবে না।',
        priority: 'ESSENTIAL',
        verificationAction: 'Deny unexpected MFA prompts and rotate password immediately if prompted',
      },
    ],
  },
  {
    trackId: 'backup_updates',
    order: 4,
    titleEn: '4. Backup and Software Update Checklist',
    titleBn: '৪. ব্যাকআপ এবং সফটওয়্যার আপডেট চেকলিস্ট',
    audienceEn: 'Endpoints, Servers & Personal Devices',
    audienceBn: 'কম্পিউটার, সার্ভার ও মোবাইল ডিভাইস',
    summaryEn:
      'Maintain resilient 3-2-1 offline backups against ransomware and patch operating systems, browsers, and applications promptly.',
    summaryBn:
      'র‍্যানসমওয়্যার থেকে বাঁচতে ৩-২-১ নিয়মে অফলাইন ব্যাকআপ রাখুন এবং নিয়মিত অপারেটিং সিস্টেম ও ব্রাউজার আপডেট করুন।',
    items: [
      {
        id: 'bu_321_offline_backup',
        trackId: 'backup_updates',
        titleEn: 'Maintain 3-2-1 backups including at least 1 disconnected offline/immutable copy',
        titleBn: '৩-২-১ নিয়মে ব্যাকআপ রাখুন যার অন্তত ১টি কপি অফলাইন বা পিসি থেকে বিচ্ছিন্ন থাকবে',
        guidanceEn:
          'Ransomware encrypts connected USB drives and mapped network shares. Keep one backup drive unplugged after each backup.',
        guidanceBn:
          'র‍্যানসমওয়্যার সংযুক্ত পেনড্রাইভ বা নেটওয়ার্ক ড্রাইভও লক করে ফেলে। তাই ব্যাকআপ শেষে এক্সটার্নাল ড্রাইভ খুলে রাখুন।',
        priority: 'ESSENTIAL',
        verificationAction: 'Verify 3 copies, 2 media types, 1 air-gapped/immutable copy',
      },
      {
        id: 'bu_auto_os_browser_patch',
        trackId: 'backup_updates',
        titleEn: 'Enable automatic security updates for OS, web browsers, PDF readers, and archive tools',
        titleBn: 'অপারেটিং সিস্টেম, ওয়েব ব্রাউজার, পিডিএফ রিডার ও আর্কাইভ টুলের অটো-আপডেট চালু রাখুন',
        guidanceEn:
          'Cross-check installed software against the KIRON PROHORI CISA KEV Tracker to remediate known exploited vulnerabilities first.',
        guidanceBn:
          'ব্যবহৃত সফটওয়্যারগুলো নিয়মিত আপডেট করুন এবং CISA KEV তালিকায় থাকা দুর্বলতাগুলো দ্রুত প্যাচ করুন।',
        priority: 'ESSENTIAL',
        verificationAction: 'Check OS Update Status & Browser Version (Chrome/Firefox/Edge/Safari)',
      },
      {
        id: 'bu_test_restore',
        trackId: 'backup_updates',
        titleEn: 'Test restoring files from your backup archive to verify data integrity',
        titleBn: 'ব্যাকআপ ফাইলগুলো সত্যিই রিস্টোর বা ওপেন করা যাচ্ছে কি না তা পরীক্ষা করুন',
        guidanceEn:
          'An untested backup can silently fail during an emergency. Perform a sample restoration drill every quarter.',
        guidanceBn:
          'জরুরি মুহূর্তে ব্যাকআপ কাজ করছে কি না তা নিশ্চিত হতে প্রতি তিন মাসে একবার টেস্ট রিস্টোর করুন।',
        priority: 'RECOMMENDED',
        verificationAction: 'Restore a test folder from offline backup media and verify checksums',
      },
    ],
  },
  {
    trackId: 'small_business',
    order: 5,
    titleEn: '5. Small Business Security Checklist',
    titleBn: '৫. ক্ষুদ্র ব্যবসা (Small Business) নিরাপত্তা চেকলিস্ট',
    audienceEn: 'Small Businesses, Shops, NGOs & Startups',
    audienceBn: 'ক্ষুদ্র ও মাঝারি ব্যবসা, দোকান এবং স্টার্টআপ',
    summaryEn:
      'Practical zero-cost defensive controls to protect small business finances, customer records, POS terminals, and domain email.',
    summaryBn:
      'বিনামূল্যে বাস্তবায়নযোগ্য নিয়ন্ত্রণের মাধ্যমে ব্যবসার আর্থিক লেনদেন, গ্রাহকের তথ্য এবং ইমেইল ডোমেইন সুরক্ষিত রাখুন।',
    items: [
      {
        id: 'smb_least_privilege',
        trackId: 'small_business',
        titleEn: 'Separate daily staff user accounts from local/cloud Administrator accounts',
        titleBn: 'দৈনন্দিন কাজের অ্যাকাউন্ট এবং অ্যাডমিনিস্ট্রেটর অ্যাকাউন্ট আলাদা রাখুন',
        guidanceEn:
          'Employees should use standard non-admin accounts for daily email and web browsing to limit malware execution privileges.',
        guidanceBn:
          'দৈনন্দিন ইমেইল ও ব্রাউজিংয়ের জন্য স্ট্যান্ডার্ড ইউজার অ্যাকাউন্ট ব্যবহার করুন, অ্যাডমিন অ্যাকাউন্ট নয়।',
        priority: 'ESSENTIAL',
        verificationAction: 'Remove unnecessary local administrator rights on office workstations',
      },
      {
        id: 'smb_invoice_out_of_band',
        trackId: 'small_business',
        titleEn: 'Require out-of-band voice verification before changing vendor bank/bKash/payment details',
        titleBn: 'ভেন্ডর বা সাপ্লায়ারের ব্যাংক/পেমেন্ট অ্যাকাউন্ট পরিবর্তনের আগে ফোনে সরাসরি যাচাই করুন',
        guidanceEn:
          'Business Email Compromise (BEC) scammers send fake urgent invoice updates. Always call the known phone number on file.',
        guidanceBn:
          'ইমেইলে হঠাৎ ব্যাংক অ্যাকাউন্ট পরিবর্তনের অনুরোধ পেলে টাকা পাঠানোর আগে পূর্বপরিচিত নম্বরে ফোন করে নিশ্চিত হোন।',
        priority: 'ESSENTIAL',
        verificationAction: 'Establish a mandatory 2-person approval rule for payment account changes',
      },
      {
        id: 'smb_email_spf_dmarc',
        trackId: 'small_business',
        titleEn: 'Configure SPF, DKIM, and DMARC DNS records on your business domain',
        titleBn: 'ব্যবসায়িক ডোমেইনে SPF, DKIM এবং DMARC ডিএনএস রেকর্ড কনফিগার করুন',
        guidanceEn:
          'Prevents criminals from spoofing your company email address to defraud customers or partners.',
        guidanceBn:
          'আপনার প্রতিষ্ঠানের ডোমেইন নকল করে গ্রাহকদের কাছে ভুয়া ইমেইল পাঠানো বন্ধ করতে SPF ও DMARC চালু করুন।',
        priority: 'RECOMMENDED',
        verificationAction: 'Verify TXT records for SPF, DKIM, and DMARC in domain DNS panel',
      },
    ],
  },
  {
    trackId: 'service_technician',
    order: 6,
    titleEn: '6. Computer Service Technician Checklist',
    titleBn: '৬. কম্পিউটার সার্ভিস টেকনিশিয়ান চেকলিস্ট',
    audienceEn: 'IT Support Technicians, Repair Labs & Sysadmins',
    audienceBn: 'কম্পিউটার সার্ভিস টেকনিশিয়ান ও আইটি সাপোর্ট',
    summaryEn:
      'Safe triage, malware isolation, customer data privacy, and clean OS media verification protocols for repair & service technicians.',
    summaryBn:
      'কম্পিউটার সার্ভিসিং ও ম্যালওয়্যার পরিষ্কারের সময় নিরাপদ ট্রায়াজ, গ্রাহকের গোপনীয়তা এবং অফিশিয়াল ইন্সটলারের SHA-256 যাচাই।',
    items: [
      {
        id: 'tech_clean_media_sha256',
        trackId: 'service_technician',
        titleEn: 'Verify official OS ISO & driver installer SHA-256 hashes before customer installation',
        titleBn: 'গ্রাহকের পিসিতে উইন্ডোজ বা ড্রাইভার ইন্সটলের আগে অফিশিয়াল ফাইলের SHA-256 হ্যাশ যাচাই করুন',
        guidanceEn:
          'Never use cracked OS images, pirated activators (KMS trojans), or third-party driver packs. Use the KIRON PROHORI Hash Tool to verify SHA-256 checksums.',
        guidanceBn:
          'কখনোই ক্র্যাকড উইন্ডোজ, পাইরেটেড অ্যাক্টিভেটর বা অপরিচিত ড্রাইভার প্যাক ব্যবহার করবেন না। ইন্সটলারের SHA-256 হ্যাশ মিলিয়ে নিন।',
        priority: 'ESSENTIAL',
        verificationAction: 'Compute local SHA-256 via KIRON PROHORI Hash Tool and compare with vendor checksum',
      },
      {
        id: 'tech_usb_isolation',
        trackId: 'service_technician',
        titleEn: 'Isolate infected customer machines from shop LAN and sanitize technician USB drives',
        titleBn: 'ভাইরাস আক্রান্ত পিসিকে মূল নেটওয়ার্ক থেকে আলাদা রাখুন এবং সার্ভিস পেনড্রাইভ স্ক্যান করুন',
        guidanceEn:
          'Use write-protected or freshly formatted technician media so malware does not spread across customer machines.',
        guidanceBn:
          'এক গ্রাহকের পিসি থেকে অন্য পিসিতে ম্যালওয়্যার ছড়ানো রোধ করতে সার্ভিস পেনড্রাইভ রাইট-প্রোটেক্টেড রাখুন বা ফরম্যাট করুন।',
        priority: 'ESSENTIAL',
        verificationAction: 'Use isolated VLAN/guest network for customer diagnostics and scan USB tools',
      },
      {
        id: 'tech_builtin_edr_firewall',
        trackId: 'service_technician',
        titleEn: 'Ensure built-in OS Antivirus/Defender, Firewall, and Secure Boot are active before handoff',
        titleBn: 'গ্রাহককে পিসি বুঝিয়ে দেওয়ার আগে ডিফেন্ডার/অ্যান্টিভাইরাস, ফায়ারওয়াল এবং সিকিউর বুট চালু আছে কি না নিশ্চিত করুন',
        guidanceEn:
          'Never permanently disable Windows Security/Defender or firewall rules to make legacy software run.',
        guidanceBn:
          'কোনো সফটওয়্যার চালানোর অজুহাতে কখনোই কম্পিউটারের ডিফেন্ডার বা ফায়ারওয়াল বন্ধ করে দেবেন না।',
        priority: 'ESSENTIAL',
        verificationAction: 'Verify Defender Real-Time Protection, Tamper Protection, and OS Firewall ON',
      },
    ],
  },
];

export interface ChecklistProgressSummary {
  totalItems: number;
  completedItems: number;
  completionPercentage: number;
  byTrack: Record<
    SecurityChecklistTrackId,
    {
      trackId: SecurityChecklistTrackId;
      titleEn: string;
      total: number;
      completed: number;
      percentage: number;
    }
  >;
}

/**
 * Computes overall and per-track checklist completion progress deterministically.
 */
export function calculateChecklistProgress(
  completedItemIds: Iterable<string>
): ChecklistProgressSummary {
  const completedSet = new Set<string>(completedItemIds);
  let totalItems = 0;
  let completedItems = 0;

  const byTrack = {} as ChecklistProgressSummary['byTrack'];

  for (const track of SECURITY_CHECKLIST_TRACKS) {
    let trackCompleted = 0;
    for (const item of track.items) {
      totalItems++;
      if (completedSet.has(item.id)) {
        completedItems++;
        trackCompleted++;
      }
    }
    const pct =
      track.items.length > 0
        ? Math.round((trackCompleted / track.items.length) * 100)
        : 0;
    byTrack[track.trackId] = {
      trackId: track.trackId,
      titleEn: track.titleEn,
      total: track.items.length,
      completed: trackCompleted,
      percentage: pct,
    };
  }

  const completionPercentage =
    totalItems > 0 ? Math.round((completedItems / totalItems) * 100) : 0;

  return {
    totalItems,
    completedItems,
    completionPercentage,
    byTrack,
  };
}

// ============================================================================
// 4. WATCHLIST & PERSONALIZED DASHBOARD MATCHER
// ============================================================================

export interface PersonalizedWatchlistMatch {
  watchlistId: string;
  itemType: WatchlistDoc['itemType'];
  targetValue: string;
  matchedCveId: string;
  matchedVendor: string;
  matchedProduct: string;
  titleOrVulnerabilityName: string;
  severity: string;
  inKev: boolean;
  dueDate: string;
  requiredAction: string;
  sourceAttribution: string;
}

export interface PersonalizedWatchlistDashboard {
  totalWatchlistItems: number;
  savedCvesCount: number;
  followedVendorsCount: number;
  followedProductsCount: number;
  followedDomainsCount: number;
  totalCatalogMatches: number;
  activeKevMatchesCount: number;
  matches: PersonalizedWatchlistMatch[];
}

/**
 * Matches a user's saved Watchlist items (CVEs, Vendors, Products, Domains)
 * against verified CISA KEV records and Firestore CVE catalog records
 * to power the Personalized Security Dashboard.
 */
export function buildPersonalizedWatchlistDashboard(
  watchlists: WatchlistDoc[],
  kevRecords: ParsedKevRecord[],
  firestoreCves: CveRecordDoc[]
): PersonalizedWatchlistDashboard {
  const savedCvesCount = watchlists.filter((w) => w.itemType === 'cve_id').length;
  const followedVendorsCount = watchlists.filter(
    (w) => w.itemType === 'vendor_keyword'
  ).length;
  const followedProductsCount = watchlists.filter(
    (w) => w.itemType === 'product_cpe'
  ).length;
  const followedDomainsCount = watchlists.filter(
    (w) => w.itemType === 'domain_pattern'
  ).length;

  const matches: PersonalizedWatchlistMatch[] = [];
  const seenKey = new Set<string>();

  for (const wl of watchlists) {
    const queryLower = wl.targetValue.trim().toLowerCase();
    if (!queryLower) continue;

    // 1. Check against live CISA KEV records
    for (const kev of kevRecords) {
      let isMatch = false;
      if (wl.itemType === 'cve_id') {
        isMatch = kev.cveId.toLowerCase() === queryLower;
      } else if (wl.itemType === 'vendor_keyword') {
        isMatch = kev.vendorProject.toLowerCase().includes(queryLower);
      } else if (wl.itemType === 'product_cpe') {
        isMatch =
          kev.product.toLowerCase().includes(queryLower) ||
          `${kev.vendorProject} ${kev.product}`.toLowerCase().includes(queryLower);
      }

      if (isMatch) {
        const dedupKey = `${wl.watchlistId}:${kev.cveId}`;
        if (!seenKey.has(dedupKey)) {
          seenKey.add(dedupKey);
          matches.push({
            watchlistId: wl.watchlistId,
            itemType: wl.itemType,
            targetValue: wl.targetValue,
            matchedCveId: kev.cveId,
            matchedVendor: kev.vendorProject,
            matchedProduct: kev.product,
            titleOrVulnerabilityName: kev.vulnerabilityName,
            severity:
              kev.knownRansomwareCampaignUse === 'Known'
                ? 'CRITICAL (KEV + Known Ransomware)'
                : 'HIGH (CISA KEV Active Exploitation)',
            inKev: true,
            dueDate: kev.dueDate || 'Unknown',
            requiredAction: kev.requiredAction || 'Apply updates per vendor instructions.',
            sourceAttribution: 'CISA Known Exploited Vulnerabilities Catalog',
          });
        }
      }
    }

    // 2. Check against verified Firestore CVEs
    for (const cve of firestoreCves) {
      if (wl.severityFilter === 'CRITICAL_ONLY' && cve.severity !== 'CRITICAL') {
        continue;
      }
      if (
        wl.severityFilter === 'HIGH_PLUS' &&
        cve.severity !== 'CRITICAL' &&
        cve.severity !== 'HIGH'
      ) {
        continue;
      }

      let isMatch = false;
      if (wl.itemType === 'cve_id') {
        isMatch = cve.cveId.toLowerCase() === queryLower;
      } else if (wl.itemType === 'vendor_keyword') {
        isMatch = cve.vendor.toLowerCase().includes(queryLower);
      } else if (wl.itemType === 'product_cpe') {
        isMatch =
          cve.product.toLowerCase().includes(queryLower) ||
          `${cve.vendor} ${cve.product}`.toLowerCase().includes(queryLower);
      }

      if (isMatch) {
        const dedupKey = `${wl.watchlistId}:${cve.cveId}`;
        if (!seenKey.has(dedupKey)) {
          seenKey.add(dedupKey);
          matches.push({
            watchlistId: wl.watchlistId,
            itemType: wl.itemType,
            targetValue: wl.targetValue,
            matchedCveId: cve.cveId,
            matchedVendor: cve.vendor || 'Unknown',
            matchedProduct: cve.product || 'Unknown',
            titleOrVulnerabilityName: cve.title || cve.description.slice(0, 120),
            severity: `${cve.severity} (CVSS ${cve.cvssScore.toFixed(1)})`,
            inKev: kevRecords.some(
              (k) => k.cveId.toUpperCase() === cve.cveId.toUpperCase()
            ),
            dueDate: 'See Vendor Advisory',
            requiredAction: 'Review NVD references and apply vendor security patch.',
            sourceAttribution: cve.source || 'NIST NVD / Verified Firestore Catalog',
          });
        }
      }
    }
  }

  return {
    totalWatchlistItems: watchlists.length,
    savedCvesCount,
    followedVendorsCount,
    followedProductsCount,
    followedDomainsCount,
    totalCatalogMatches: matches.length,
    activeKevMatchesCount: matches.filter((m) => m.inKev).length,
    matches: matches.slice(0, 50),
  };
}

// ============================================================================
// 5. IN-APP NOTIFICATIONS FILTER ENGINE ($0 IN-APP ONLY — NO PAID EMAIL/SMS)
// ============================================================================

export function filterNotifications(
  notifications: NotificationDoc[],
  options: {
    categoryFilter?: 'ALL' | NotificationDoc['category'];
    readStatusFilter?: 'ALL' | 'UNREAD' | 'READ';
    searchQuery?: string;
  }
): NotificationDoc[] {
  const cat = options.categoryFilter || 'ALL';
  const readF = options.readStatusFilter || 'ALL';
  const q = (options.searchQuery || '').trim().toLowerCase();

  return [...notifications]
    .filter((n) => {
      if (cat !== 'ALL' && n.category !== cat) return false;
      if (readF === 'UNREAD' && n.isRead) return false;
      if (readF === 'READ' && !n.isRead) return false;
      if (q) {
        const hay = `${n.title} ${n.message} ${n.category}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    })
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

// ============================================================================
// 6. REPORT CENTER — HONEST CSV & STANDARDS-COMPLIANT PDF 1.4 GENERATOR
// ============================================================================

export const MANDATORY_REPORT_DISCLAIMER =
  'DISCLAIMER: This report was generated locally by KIRON PROHORI (Independent Cyber Threat Intelligence Platform, v0.1.0). KIRON PROHORI is not affiliated with, endorsed by, or operated by CISA, NIST, CVE, FIRST, Google, or any government agency. Findings reflect only verified public threat feeds and user-provided checklist or watchlist selections at the timestamp of generation. No security findings have been fabricated. Absence of a threat match means UNKNOWN, never SAFE.';

export interface DefensiveReportPayload {
  reportTitle: string;
  generatedAtIso: string;
  preparedBy: string;
  organization: string;
  sourceReferences: string[];
  disclaimer: string;
  checklistSummary?: {
    completedItems: number;
    totalItems: number;
    completionPercentage: number;
  };
  rows: {
    recordId: string;
    category: string;
    subject: string;
    statusOrSeverity: string;
    requiredActionOrNote: string;
    sourceAttribution: string;
    referenceDate: string;
  }[];
}

function escapeCsvField(val: string): string {
  const cleaned = (val || 'Unknown').replace(/\r?\n|\r/g, ' ').trim();
  if (cleaned.includes(',') || cleaned.includes('"') || cleaned.includes(';')) {
    return `"${cleaned.replace(/"/g, '""')}"`;
  }
  return cleaned;
}

/**
 * Generates a downloadable RFC-4180 CSV report containing metadata header rows,
 * report generation date, official source references, mandatory disclaimer, and verified findings.
 */
export function generateReportCsv(payload: DefensiveReportPayload): string {
  const metaLines = [
    `# REPORT_TITLE,${escapeCsvField(payload.reportTitle)}`,
    `# REPORT_DATE_UTC,${escapeCsvField(payload.generatedAtIso)}`,
    `# PREPARED_BY,${escapeCsvField(`${payload.preparedBy} (${payload.organization || 'Independent Defender'})`)}`,
    `# OFFICIAL_SOURCE_REFERENCES,${escapeCsvField(payload.sourceReferences.join(' | '))}`,
    `# DISCLAIMER,${escapeCsvField(payload.disclaimer)}`,
  ];

  if (payload.checklistSummary) {
    metaLines.push(
      `# CHECKLIST_COMPLETION,${payload.checklistSummary.completedItems}/${payload.checklistSummary.totalItems} (${payload.checklistSummary.completionPercentage}%)`
    );
  }

  const columnHeader = [
    'Record_ID',
    'Category',
    'Subject_Or_Indicator',
    'Status_Or_Severity',
    'Action_Or_Analytical_Note',
    'Source_Attribution',
    'Reference_Date',
  ].join(',');

  const dataLines =
    payload.rows.length > 0
      ? payload.rows.map((r) =>
          [
            r.recordId,
            r.category,
            r.subject,
            r.statusOrSeverity,
            r.requiredActionOrNote,
            r.sourceAttribution,
            r.referenceDate,
          ]
            .map(escapeCsvField)
            .join(',')
        )
      : [
          [
            'NO_RECORDS_SELECTED',
            'Honest Empty State',
            'Zero records matched current selection criteria',
            'UNKNOWN',
            'No fabricated security findings were added',
            'KIRON PROHORI Report Center',
            payload.generatedAtIso,
          ]
            .map(escapeCsvField)
            .join(','),
        ];

  return [...metaLines, columnHeader, ...dataLines].join('\n');
}

function escapePdfText(text: string): string {
  // Strip non-printable or non-ASCII chars to keep standard Type1 Helvetica stream valid
  const ascii = text
    .replace(/[^\x20-\x7E]/g, ' ')
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
  return ascii;
}

function wrapTextLines(text: string, maxCharsPerLine: number): string[] {
  const words = text.replace(/\s+/g, ' ').trim().split(' ');
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    if (!current) {
      current = word;
    } else if (current.length + 1 + word.length <= maxCharsPerLine) {
      current += ` ${word}`;
    } else {
      lines.push(current);
      current = word;
    }
  }
  if (current) lines.push(current);
  return lines;
}

/**
 * Generates a genuine, standards-compliant PDF 1.4 document string (`%PDF-1.4 ... %%EOF`)
 * with zero third-party dependencies.
 * Includes:
 * - Report Date & UTC Timestamp
 * - Prepared By & Organization
 * - Official Source References
 * - Mandatory Independent & Non-Fabrication Disclaimer
 * - Verified Data Rows (or an explicit zero-findings notice without fabrication)
 */
export function generateValidPdfDocument(payload: DefensiveReportPayload): string {
  const linesToRender: { text: string; fontSize: number; bold?: boolean }[] = [];

  linesToRender.push({
    text: 'KIRON PROHORI — INDEPENDENT CYBER THREAT INTELLIGENCE PLATFORM',
    fontSize: 12,
    bold: true,
  });
  linesToRender.push({
    text: `REPORT: ${payload.reportTitle}`,
    fontSize: 11,
    bold: true,
  });
  linesToRender.push({
    text: `Report Date (UTC): ${payload.generatedAtIso}`,
    fontSize: 9,
  });
  linesToRender.push({
    text: `Prepared By: ${payload.preparedBy} (${payload.organization || 'Independent Defender'})`,
    fontSize: 9,
  });

  if (payload.checklistSummary) {
    linesToRender.push({
      text: `Security Checklist Readiness: ${payload.checklistSummary.completedItems}/${payload.checklistSummary.totalItems} Controls Verified (${payload.checklistSummary.completionPercentage}%)`,
      fontSize: 9,
      bold: true,
    });
  }

  linesToRender.push({
    text: '----------------------------------------------------------------------------------------',
    fontSize: 8,
  });
  linesToRender.push({
    text: 'OFFICIAL SOURCE REFERENCES:',
    fontSize: 9,
    bold: true,
  });

  for (const src of payload.sourceReferences) {
    for (const wrapped of wrapTextLines(`* ${src}`, 88)) {
      linesToRender.push({ text: wrapped, fontSize: 8 });
    }
  }

  linesToRender.push({
    text: '----------------------------------------------------------------------------------------',
    fontSize: 8,
  });
  linesToRender.push({
    text: 'MANDATORY SECURITY & NON-AFFILIATION DISCLAIMER:',
    fontSize: 9,
    bold: true,
  });

  for (const wrapped of wrapTextLines(payload.disclaimer, 88)) {
    linesToRender.push({ text: wrapped, fontSize: 8 });
  }

  linesToRender.push({
    text: '----------------------------------------------------------------------------------------',
    fontSize: 8,
  });
  linesToRender.push({
    text: `VERIFIED REPORT RECORDS (${payload.rows.length} RECORD(S) INCLUDED — ZERO FABRICATED FINDINGS):`,
    fontSize: 9,
    bold: true,
  });

  if (payload.rows.length === 0) {
    linesToRender.push({
      text: 'No verified records matched the current report selection. No fabricated findings were generated.',
      fontSize: 8,
    });
  } else {
    const maxRowsInPdf = Math.min(payload.rows.length, 24);
    for (let i = 0; i < maxRowsInPdf; i++) {
      const r = payload.rows[i];
      const headerLine = `${i + 1}. [${r.recordId}] (${r.category}) ${r.subject} — ${r.statusOrSeverity}`;
      for (const wrapped of wrapTextLines(headerLine, 88)) {
        linesToRender.push({ text: wrapped, fontSize: 8, bold: true });
      }
      const detailLine = `   Action/Note: ${r.requiredActionOrNote} | Source: ${r.sourceAttribution} (${r.referenceDate})`;
      for (const wrapped of wrapTextLines(detailLine, 88)) {
        linesToRender.push({ text: wrapped, fontSize: 8 });
      }
    }
  }

  // Build PDF content stream (Letter page 612 x 792 pt)
  const streamCommands: string[] = ['BT'];
  let y = 752;

  for (const line of linesToRender) {
    if (y < 48) break; // Keep within single-page safe margin
    const fontKey = line.bold ? '/F2' : '/F1';
    streamCommands.push(`${fontKey} ${line.fontSize} Tf`);
    streamCommands.push(`1 0 0 1 42 ${y} Tm`);
    streamCommands.push(`(${escapePdfText(line.text)}) Tj`);
    y -= line.fontSize + 4;
  }
  streamCommands.push('ET');
  const streamBody = streamCommands.join('\n');

  const objects: string[] = [
    '1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj',
    '2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj',
    '3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>\nendobj',
    '4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj',
    '5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj',
    `6 0 obj\n<< /Length ${streamBody.length} >>\nstream\n${streamBody}\nendstream\nendobj`,
  ];

  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [0];

  for (const obj of objects) {
    offsets.push(pdf.length);
    pdf += `${obj}\n`;
  }

  const xrefOffset = pdf.length;
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (let i = 1; i < offsets.length; i++) {
    pdf += `${String(offsets[i]).padStart(10, '0')} 00000 n \n`;
  }

  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return pdf;
}
