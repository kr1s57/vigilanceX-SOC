package middleware

import (
	"encoding/json"
	"net/http"

	"github.com/kr1s57/vigilancex/internal/license"
)

// LicenseResponse is the JSON response when license check fails
type LicenseResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Status  string `json:"status"`
}

// RequireLicense middleware checks if there is a valid license
func RequireLicense(client *license.Client) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if client == nil {
				// License system not enabled, allow through
				next.ServeHTTP(w, r)
				return
			}

			if !client.IsLicensed() {
				status := client.GetStatus()
				writeUnlicensedResponse(w, status)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireFeature middleware checks if a specific feature is licensed
func RequireFeature(client *license.Client, feature string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if client == nil {
				// License system not enabled, allow through
				next.ServeHTTP(w, r)
				return
			}

			if !client.HasFeature(feature) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				json.NewEncoder(w).Encode(LicenseResponse{
					Error:   "feature_not_licensed",
					Message: "This feature requires a license upgrade.",
					Status:  "feature_unavailable",
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// OptionalLicense middleware adds license info to context but doesn't block
// Useful for routes that want to display license status without enforcing
func OptionalLicense(client *license.Client) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Just pass through - license info is available via client.GetStatus()
			next.ServeHTTP(w, r)
		})
	}
}

// writeUnlicensedResponse sends a JSON response when license is invalid
func writeUnlicensedResponse(w http.ResponseWriter, status *license.LicenseStatus) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusPaymentRequired) // 402 Payment Required

	var message string
	switch status.Status {
	case "not_activated":
		message = "License not activated. Please enter a valid license key."
	case "expired":
		message = "License has expired. Please renew your license."
	case "revoked":
		message = "License has been revoked. Please contact support."
	case "grace_expired":
		message = "License grace period has expired. Please contact the license server."
	default:
		message = "License invalid. Please contact support."
	}

	json.NewEncoder(w).Encode(LicenseResponse{
		Error:   "license_invalid",
		Message: message,
		Status:  status.Status,
	})
}
