/**
 * KIRON PROHORI — Shared Input Validation, Defanging, Credential Leak Guard & Rate Limiter
 * Synchronized verbatim with firebase-blueprint.json and firestore.rules.
 */

export const ID_REGEX = /^[a-zA-Z0-9_\-]+$/;

// Patterns that indicate someone pasted raw credentials, session cookies, or private keys
const FORBIDDEN_CREDENTIAL_PATTERNS: { pattern: RegExp; reason: string }[] = [
  { pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/i, reason: 'Private cryptographic key detected' },
  { pattern: /\b(password|passwd|pwd)\s*[:=]\s*\S+/i, reason: 'Plaintext password assignment detected' },
  { pattern: /\b(set-cookie|sessionid|phpsessid|connect\.sid)\s*[:=]/i, reason: 'Session cookie header or value detected' },
  { pattern: /\bBearer\s+eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+/i, reason: 'Raw JWT Bearer token detected' },
  { pattern: /\bAIza[0-9A-Za-z_\-]{35}\b/, reason: 'Raw API key string detected' },
];

export interface ValidationResult {
  valid: boolean;
  error?: string;
  sanitizedValue?: string;
}

export function validateDocumentId(id: unknown): ValidationResult {
  if (typeof id !== 'string') {
    return { valid: false, error: 'Document ID must be a string.' };
  }
  const trimmed = id.trim();
  if (trimmed.length < 1 || trimmed.length > 128) {
    return { valid: false, error: 'Document ID must be between 1 and 128 characters.' };
  }
  if (!ID_REGEX.test(trimmed)) {
    return {
      valid: false,
      error: 'Document ID may only contain alphanumeric characters, underscores, and hyphens (^[a-zA-Z0-9_\\-]+$).',
    };
  }
  return { valid: true, sanitizedValue: trimmed };
}

export function checkNoStolenCredentialsOrSecrets(text: string): ValidationResult {
  for (const rule of FORBIDDEN_CREDENTIAL_PATTERNS) {
    if (rule.pattern.test(text)) {
      return {
        valid: false,
        error: `Security Policy Rejection: ${rule.reason}. Never submit passwords, cookies, tokens, or private keys.`,
      };
    }
  }
  return { valid: true };
}

export function validateBoundedString(
  value: unknown,
  fieldName: string,
  minLength: number,
  maxLength: number
): ValidationResult {
  if (typeof value !== 'string') {
    return { valid: false, error: `${fieldName} must be a string.` };
  }
  const trimmed = value.trim();
  if (trimmed.length < minLength) {
    return {
      valid: false,
      error: `${fieldName} must be at least ${minLength} characters (received ${trimmed.length}).`,
    };
  }
  if (trimmed.length > maxLength) {
    return {
      valid: false,
      error: `${fieldName} exceeds maximum length of ${maxLength} characters.`,
    };
  }
  const secretCheck = checkNoStolenCredentialsOrSecrets(trimmed);
  if (!secretCheck.valid) {
    return secretCheck;
  }
  return { valid: true, sanitizedValue: trimmed };
}

/**
 * Automatically defangs URLs and IP addresses so malicious links cannot be clicked.
 * e.g. https://bad.example.com/login -> hxxps://bad[.]example[.]com/login
 */
export function defangIndicatorText(raw: string): string {
  return raw
    .trim()
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^https:\/\//i, 'hxxps://')
    .replace(/\./g, '[.]');
}

/**
 * Client-side sliding window rate limiter to prevent rapid mutation spamming
 */
class ClientRateLimiter {
  private timestamps: Map<string, number[]> = new Map();

  public checkLimit(actionKey: string, maxRequests = 12, windowMs = 60_000): { allowed: boolean; retryAfterSec: number } {
    const now = Date.now();
    const history = (this.timestamps.get(actionKey) || []).filter((ts) => now - ts < windowMs);
    if (history.length >= maxRequests) {
      const oldest = history[0];
      const retryAfterSec = Math.max(1, Math.ceil((windowMs - (now - oldest)) / 1000));
      return { allowed: false, retryAfterSec };
    }
    history.push(now);
    this.timestamps.set(actionKey, history);
    return { allowed: true, retryAfterSec: 0 };
  }
}

export const clientRateLimiter = new ClientRateLimiter();
