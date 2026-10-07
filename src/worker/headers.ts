/**
 * Security headers for every response that passes through the Worker — HTML
 * pages and root-level files. (Content-hashed assets under /assets, /demo,
 * /og and /icons are served straight from the edge; CSP is per document, so
 * that is where it matters.)
 *
 * HTML responses use a fresh nonce and strict-dynamic for AdSense scripts.
 * HTTPS images, connections and frames support Google's changing ad domains.
 * The single inline script is the theme bootstrap in
 * site/partials/head.html; its hash is pinned here and test/headers.test.ts
 * fails if the script changes without this constant being updated.
 */
export const THEME_SCRIPT_HASH = 'sha256-Hxg0M8IuaBC2jE6SyIUx6Tkv9cudGL8JfSeBUGCOXOo='

export function contentSecurityPolicy(nonce?: string): string {
  return [
    "default-src 'self'",
    nonce
      ? `script-src 'nonce-${nonce}' 'strict-dynamic' 'unsafe-eval' https: '${THEME_SCRIPT_HASH}'`
      : `script-src 'self' '${THEME_SCRIPT_HASH}'`,
    "style-src 'self' 'unsafe-inline'", // inline style="" attributes throughout the pages
    "img-src 'self' https: data: blob:", // blob: for image previews the hex inspector extracts
    "media-src 'self' blob:",
    "connect-src 'self' https:",
    "frame-src https:",
    "worker-src 'self'",
    "manifest-src 'self'",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; ')
}

export const CSP = contentSecurityPolicy()

export const SECURITY_HEADERS: Record<string, string> = {
  'content-security-policy': CSP,
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
  'cross-origin-opener-policy': 'same-origin',
}

/** Returns a copy of the response with the security headers set (asset responses have immutable headers). */
export function withSecurityHeaders(res: Response, nonce?: string): Response {
  const out = new Response(res.body, res)
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) out.headers.set(name, value)
  if (nonce) out.headers.set('content-security-policy', contentSecurityPolicy(nonce))
  return out
}
