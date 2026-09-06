"""Production Security Headers Middleware for Cybersecurity API."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Enforces strict production security headers according to OWASP guidelines."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)

        # 1. Content Security Policy (allows self and safe CDN resources for Cytoscape / Vis.js visualizer)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net data:; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'self';"
        )

        # 2. Prevent MIME type sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"

        # 3. Anti-Clickjacking
        response.headers["X-Frame-Options"] = "DENY"

        # 4. Referrer Policy
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # 5. Prevent caching of sensitive investigation data
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

        # 6. Browser Feature Policy
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )

        return response

