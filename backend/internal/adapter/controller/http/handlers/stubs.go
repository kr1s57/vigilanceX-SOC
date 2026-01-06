package handlers

import (
	"encoding/json"
	"net/http"
	"time"
)

// StubStatsOverview returns empty but valid overview stats
func StubStatsOverview(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"stats": map[string]interface{}{
			"total_events":    0,
			"blocked_events":  0,
			"block_rate":      0.0,
			"unique_ips":      0,
			"critical_events": 0,
			"high_events":     0,
			"medium_events":   0,
			"low_events":      0,
		},
		"by_log_type": map[string]int{
			"WAF":       0,
			"IPS":       0,
			"ATP":       0,
			"Firewall":  0,
			"VPN":       0,
		},
		"top_attackers": []interface{}{},
		"top_targets":   []interface{}{},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// StubEventsTimeline returns empty but valid timeline data
func StubEventsTimeline(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	timeline := make([]map[string]interface{}, 0, 24)

	// Generate 24 hours of empty data points
	for i := 23; i >= 0; i-- {
		t := now.Add(-time.Duration(i) * time.Hour)
		timeline = append(timeline, map[string]interface{}{
			"time":           t.Format(time.RFC3339),
			"total_events":   0,
			"blocked_events": 0,
			"unique_ips":     0,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": timeline,
	})
}

// StubEventsList returns empty but valid events list
func StubEventsList(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"data": []interface{}{},
		"pagination": map[string]interface{}{
			"total":    0,
			"limit":    50,
			"offset":   0,
			"has_more": false,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// StubBansList returns empty but valid bans list
func StubBansList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": []interface{}{},
	})
}

// StubBansStats returns empty but valid ban stats
func StubBansStats(w http.ResponseWriter, r *http.Request) {
	response := map[string]interface{}{
		"total_active_bans":    0,
		"total_permanent_bans": 0,
		"total_expired_bans":   0,
		"bans_last_24h":        0,
		"unbans_last_24h":      0,
		"recidivist_ips":       0,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// StubThreatsList returns empty but valid threats list
func StubThreatsList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": []interface{}{},
	})
}

// StubAnomaliesList returns empty but valid anomalies list
func StubAnomaliesList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"data": []interface{}{},
	})
}

// StubWebSocket handles WebSocket upgrade request (placeholder)
func StubWebSocket(w http.ResponseWriter, r *http.Request) {
	// For now, just return a message indicating WS is not fully implemented
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "WebSocket endpoint - connect via ws://",
		"status":  "available",
	})
}
