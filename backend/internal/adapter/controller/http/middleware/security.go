package middleware

import (
	"net/http"
)

// SecurityHeaders adds security-related HTTP headers to all responses
// v3.57.106: OWASP security headers
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Clickjacking protection - deny framing
		w.Header().Set("X-Frame-Options", "DENY")

		// XSS protection (legacy but still useful for older browsers)
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Referrer policy - don't leak referrer info
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions policy - restrict browser features
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		// Content Security Policy (CSP) - restrict resource loading
		// Note: 'unsafe-inline' needed for React styles, adjust as needed
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' 'unsafe-eval'; "+
				"style-src 'self' 'unsafe-inline'; "+
				"img-src 'self' data: https:; "+
				"font-src 'self' data:; "+
				"connect-src 'self' wss: ws:; "+
				"frame-ancestors 'none';")

		// Strict Transport Security (only if HTTPS)
		// This header tells browsers to always use HTTPS
		if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}
