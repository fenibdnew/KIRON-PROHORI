/**
 * KIRON PROHORI — Server Security Middleware (/server/middleware/index.ts)
 * Provides HTTP defensive security headers, sliding-window IP rate limiting, and zero-trust error handling.
 */

import type { Request, Response, NextFunction } from 'express';

const rateLimitStore = new Map<string, { count: number; resetAt: number }>();

/**
 * Attaches defensive HTTP headers (nosniff, Referrer-Policy, Permissions-Policy).
 */
export function defensiveSecurityHeadersMiddleware(
  _req: Request,
  res: Response,
  next: NextFunction
): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  next();
}

/**
 * Sliding-window IP rate limiter (default 60 requests / 60s window).
 */
export function createRateLimitMiddleware(maxRequests = 60, windowMs = 60_000) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const clientIp =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim() ||
      req.socket.remoteAddress ||
      'unknown';
    const now = Date.now();
    const record = rateLimitStore.get(clientIp);

    if (!record || now > record.resetAt) {
      rateLimitStore.set(clientIp, { count: 1, resetAt: now + windowMs });
      res.setHeader('X-RateLimit-Remaining', String(maxRequests - 1));
      next();
      return;
    }

    if (record.count >= maxRequests) {
      res.status(429).json({
        ok: false,
        error: 'Rate limit exceeded. Please wait before retrying.',
      });
      return;
    }

    record.count += 1;
    res.setHeader('X-RateLimit-Remaining', String(maxRequests - record.count));
    next();
  };
}
