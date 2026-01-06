package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

// Logger returns a middleware that logs HTTP requests
func Logger(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				duration := time.Since(start)
				status := ww.Status()

				// Log level based on status code
				logFn := logger.Info
				if status >= 500 {
					logFn = logger.Error
				} else if status >= 400 {
					logFn = logger.Warn
				}

				logFn("HTTP request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", status,
					"duration", duration,
					"bytes", ww.BytesWritten(),
					"remote_addr", r.RemoteAddr,
					"request_id", middleware.GetReqID(r.Context()),
				)
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
