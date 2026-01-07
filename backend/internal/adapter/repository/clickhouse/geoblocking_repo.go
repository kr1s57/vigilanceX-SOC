package clickhouse

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/kr1s57/vigilancex/internal/entity"
)

// GeoblockingRepository handles geoblocking rules persistence in ClickHouse
type GeoblockingRepository struct {
	conn *Connection
}

// NewGeoblockingRepository creates a new geoblocking repository
func NewGeoblockingRepository(conn *Connection) *GeoblockingRepository {
	return &GeoblockingRepository{conn: conn}
}

// GetAllRules retrieves all geoblocking rules
func (r *GeoblockingRepository) GetAllRules(ctx context.Context) ([]entity.GeoBlockRule, error) {
	query := `
		SELECT
			toString(id) as id,
			rule_type,
			target,
			action,
			score_modifier,
			reason,
			is_active,
			created_by,
			created_at,
			updated_at
		FROM geoblock_rules FINAL
		ORDER BY rule_type, target
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query geoblock rules: %w", err)
	}
	defer rows.Close()

	var rules []entity.GeoBlockRule
	for rows.Next() {
		var rule entity.GeoBlockRule
		var isActive uint8

		if err := rows.Scan(
			&rule.ID,
			&rule.RuleType,
			&rule.Target,
			&rule.Action,
			&rule.ScoreModifier,
			&rule.Reason,
			&isActive,
			&rule.CreatedBy,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan geoblock rule: %w", err)
		}

		rule.IsActive = isActive == 1
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetActiveRules retrieves only active geoblocking rules
func (r *GeoblockingRepository) GetActiveRules(ctx context.Context) ([]entity.GeoBlockRule, error) {
	query := `
		SELECT
			toString(id) as id,
			rule_type,
			target,
			action,
			score_modifier,
			reason,
			is_active,
			created_by,
			created_at,
			updated_at
		FROM geoblock_rules FINAL
		WHERE is_active = 1
		ORDER BY rule_type, target
	`

	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query active geoblock rules: %w", err)
	}
	defer rows.Close()

	var rules []entity.GeoBlockRule
	for rows.Next() {
		var rule entity.GeoBlockRule
		var isActive uint8

		if err := rows.Scan(
			&rule.ID,
			&rule.RuleType,
			&rule.Target,
			&rule.Action,
			&rule.ScoreModifier,
			&rule.Reason,
			&isActive,
			&rule.CreatedBy,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan active geoblock rule: %w", err)
		}

		rule.IsActive = isActive == 1
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetRulesByType retrieves rules filtered by type
func (r *GeoblockingRepository) GetRulesByType(ctx context.Context, ruleType string) ([]entity.GeoBlockRule, error) {
	query := `
		SELECT
			toString(id) as id,
			rule_type,
			target,
			action,
			score_modifier,
			reason,
			is_active,
			created_by,
			created_at,
			updated_at
		FROM geoblock_rules FINAL
		WHERE rule_type = ? AND is_active = 1
		ORDER BY target
	`

	rows, err := r.conn.DB().Query(ctx, query, ruleType)
	if err != nil {
		return nil, fmt.Errorf("query geoblock rules by type: %w", err)
	}
	defer rows.Close()

	var rules []entity.GeoBlockRule
	for rows.Next() {
		var rule entity.GeoBlockRule
		var isActive uint8

		if err := rows.Scan(
			&rule.ID,
			&rule.RuleType,
			&rule.Target,
			&rule.Action,
			&rule.ScoreModifier,
			&rule.Reason,
			&isActive,
			&rule.CreatedBy,
			&rule.CreatedAt,
			&rule.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan geoblock rule: %w", err)
		}

		rule.IsActive = isActive == 1
		rules = append(rules, rule)
	}

	return rules, nil
}

// GetRuleByTarget retrieves a rule by its target (country code or ASN)
func (r *GeoblockingRepository) GetRuleByTarget(ctx context.Context, ruleType, target string) (*entity.GeoBlockRule, error) {
	query := `
		SELECT
			toString(id) as id,
			rule_type,
			target,
			action,
			score_modifier,
			reason,
			is_active,
			created_by,
			created_at,
			updated_at
		FROM geoblock_rules FINAL
		WHERE rule_type = ? AND target = ?
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, ruleType, target)

	var rule entity.GeoBlockRule
	var isActive uint8

	if err := row.Scan(
		&rule.ID,
		&rule.RuleType,
		&rule.Target,
		&rule.Action,
		&rule.ScoreModifier,
		&rule.Reason,
		&isActive,
		&rule.CreatedBy,
		&rule.CreatedAt,
		&rule.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("rule not found: %w", err)
	}

	rule.IsActive = isActive == 1
	return &rule, nil
}

// CreateRule creates a new geoblocking rule
func (r *GeoblockingRepository) CreateRule(ctx context.Context, rule *entity.GeoBlockRule) error {
	if rule.ID == "" {
		rule.ID = uuid.New().String()
	}

	now := time.Now()
	isActive := uint8(0)
	if rule.IsActive {
		isActive = 1
	}

	query := `
		INSERT INTO geoblock_rules (
			id, rule_type, target, action, score_modifier,
			reason, is_active, created_by, created_at, updated_at, version
		) VALUES (
			?, ?, ?, ?, ?,
			?, ?, ?, ?, ?, toUnixTimestamp(now())
		)
	`

	if err := r.conn.DB().Exec(ctx, query,
		rule.ID,
		rule.RuleType,
		rule.Target,
		rule.Action,
		rule.ScoreModifier,
		rule.Reason,
		isActive,
		rule.CreatedBy,
		now,
		now,
	); err != nil {
		return fmt.Errorf("create geoblock rule: %w", err)
	}

	rule.CreatedAt = now
	rule.UpdatedAt = now

	return nil
}

// UpdateRule updates an existing geoblocking rule
func (r *GeoblockingRepository) UpdateRule(ctx context.Context, rule *entity.GeoBlockRule) error {
	isActive := uint8(0)
	if rule.IsActive {
		isActive = 1
	}

	query := `
		INSERT INTO geoblock_rules (
			id, rule_type, target, action, score_modifier,
			reason, is_active, created_by, created_at, updated_at, version
		) VALUES (
			?, ?, ?, ?, ?,
			?, ?, ?, ?, now(), toUnixTimestamp(now())
		)
	`

	if err := r.conn.DB().Exec(ctx, query,
		rule.ID,
		rule.RuleType,
		rule.Target,
		rule.Action,
		rule.ScoreModifier,
		rule.Reason,
		isActive,
		rule.CreatedBy,
		rule.CreatedAt,
	); err != nil {
		return fmt.Errorf("update geoblock rule: %w", err)
	}

	rule.UpdatedAt = time.Now()
	return nil
}

// DeleteRule deletes a geoblocking rule (marks as inactive)
func (r *GeoblockingRepository) DeleteRule(ctx context.Context, id string) error {
	// Get existing rule
	query := `
		SELECT
			toString(id) as id,
			rule_type,
			target,
			action,
			score_modifier,
			reason,
			created_by,
			created_at
		FROM geoblock_rules FINAL
		WHERE id = ?
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, id)

	var rule entity.GeoBlockRule
	if err := row.Scan(
		&rule.ID,
		&rule.RuleType,
		&rule.Target,
		&rule.Action,
		&rule.ScoreModifier,
		&rule.Reason,
		&rule.CreatedBy,
		&rule.CreatedAt,
	); err != nil {
		return fmt.Errorf("rule not found: %w", err)
	}

	// Insert new version with is_active = 0
	insertQuery := `
		INSERT INTO geoblock_rules (
			id, rule_type, target, action, score_modifier,
			reason, is_active, created_by, created_at, updated_at, version
		) VALUES (
			?, ?, ?, ?, ?,
			?, 0, ?, ?, now(), toUnixTimestamp(now())
		)
	`

	if err := r.conn.DB().Exec(ctx, insertQuery,
		rule.ID,
		rule.RuleType,
		rule.Target,
		rule.Action,
		rule.ScoreModifier,
		rule.Reason,
		rule.CreatedBy,
		rule.CreatedAt,
	); err != nil {
		return fmt.Errorf("delete geoblock rule: %w", err)
	}

	return nil
}

// GetStats returns geoblocking statistics
func (r *GeoblockingRepository) GetStats(ctx context.Context) (*entity.GeoBlockStats, error) {
	stats := &entity.GeoBlockStats{
		RulesByType:   make(map[string]int),
		RulesByAction: make(map[string]int),
	}

	// Total rules
	query := `SELECT count() FROM geoblock_rules FINAL`
	var total uint64
	if err := r.conn.DB().QueryRow(ctx, query).Scan(&total); err != nil {
		return nil, fmt.Errorf("count total rules: %w", err)
	}
	stats.TotalRules = int(total)

	// Active rules
	query = `SELECT count() FROM geoblock_rules FINAL WHERE is_active = 1`
	var active uint64
	if err := r.conn.DB().QueryRow(ctx, query).Scan(&active); err != nil {
		return nil, fmt.Errorf("count active rules: %w", err)
	}
	stats.ActiveRules = int(active)

	// Rules by type
	query = `
		SELECT rule_type, count() as cnt
		FROM geoblock_rules FINAL
		WHERE is_active = 1
		GROUP BY rule_type
	`
	rows, err := r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query rules by type: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ruleType string
		var count uint64
		if err := rows.Scan(&ruleType, &count); err != nil {
			continue
		}
		stats.RulesByType[ruleType] = int(count)
	}

	// Rules by action
	query = `
		SELECT action, count() as cnt
		FROM geoblock_rules FINAL
		WHERE is_active = 1
		GROUP BY action
	`
	rows, err = r.conn.DB().Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query rules by action: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var action string
		var count uint64
		if err := rows.Scan(&action, &count); err != nil {
			continue
		}
		stats.RulesByAction[action] = int(count)
	}

	// Blocked countries
	query = `
		SELECT target
		FROM geoblock_rules FINAL
		WHERE rule_type = 'country_block' AND is_active = 1
	`
	rows, err = r.conn.DB().Query(ctx, query)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var target string
			if err := rows.Scan(&target); err == nil {
				stats.BlockedCountries = append(stats.BlockedCountries, target)
			}
		}
	}

	// Watched countries
	query = `
		SELECT target
		FROM geoblock_rules FINAL
		WHERE rule_type = 'country_watch' AND is_active = 1
	`
	rows, err = r.conn.DB().Query(ctx, query)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var target string
			if err := rows.Scan(&target); err == nil {
				stats.WatchedCountries = append(stats.WatchedCountries, target)
			}
		}
	}

	// Blocked ASNs
	query = `
		SELECT target
		FROM geoblock_rules FINAL
		WHERE rule_type = 'asn_block' AND is_active = 1
	`
	rows, err = r.conn.DB().Query(ctx, query)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var target string
			if err := rows.Scan(&target); err == nil {
				if asn, err := strconv.ParseUint(target, 10, 32); err == nil {
					stats.BlockedASNs = append(stats.BlockedASNs, uint32(asn))
				}
			}
		}
	}

	return stats, nil
}

// SaveGeoLocation caches geolocation data
func (r *GeoblockingRepository) SaveGeoLocation(ctx context.Context, geo *entity.GeoLocation) error {
	isVPN := uint8(0)
	if geo.IsVPN {
		isVPN = 1
	}
	isProxy := uint8(0)
	if geo.IsProxy {
		isProxy = 1
	}
	isTor := uint8(0)
	if geo.IsTor {
		isTor = 1
	}
	isDatacenter := uint8(0)
	if geo.IsDatacenter {
		isDatacenter = 1
	}

	query := `
		INSERT INTO ip_geolocation (
			ip, country_code, country_name, city, region,
			asn, as_org, is_vpn, is_proxy, is_tor, is_datacenter,
			latitude, longitude, last_updated, version
		) VALUES (
			toIPv4(?), ?, ?, ?, ?,
			?, ?, ?, ?, ?, ?,
			?, ?, now(), toUnixTimestamp(now())
		)
	`

	if err := r.conn.DB().Exec(ctx, query,
		geo.IP,
		geo.CountryCode,
		geo.CountryName,
		geo.City,
		geo.Region,
		geo.ASN,
		geo.ASOrg,
		isVPN,
		isProxy,
		isTor,
		isDatacenter,
		geo.Latitude,
		geo.Longitude,
	); err != nil {
		return fmt.Errorf("save geolocation: %w", err)
	}

	return nil
}

// GetGeoLocation retrieves cached geolocation data
func (r *GeoblockingRepository) GetGeoLocation(ctx context.Context, ip string) (*entity.GeoLocation, error) {
	query := `
		SELECT
			toString(ip) as ip_str,
			country_code,
			country_name,
			city,
			region,
			asn,
			as_org,
			is_vpn,
			is_proxy,
			is_tor,
			is_datacenter,
			latitude,
			longitude,
			last_updated
		FROM ip_geolocation FINAL
		WHERE ip = toIPv4(?)
		LIMIT 1
	`

	row := r.conn.DB().QueryRow(ctx, query, ip)

	var geo entity.GeoLocation
	var isVPN, isProxy, isTor, isDatacenter uint8

	if err := row.Scan(
		&geo.IP,
		&geo.CountryCode,
		&geo.CountryName,
		&geo.City,
		&geo.Region,
		&geo.ASN,
		&geo.ASOrg,
		&isVPN,
		&isProxy,
		&isTor,
		&isDatacenter,
		&geo.Latitude,
		&geo.Longitude,
		&geo.LastUpdated,
	); err != nil {
		return nil, fmt.Errorf("geolocation not found: %w", err)
	}

	geo.IsVPN = isVPN == 1
	geo.IsProxy = isProxy == 1
	geo.IsTor = isTor == 1
	geo.IsDatacenter = isDatacenter == 1

	return &geo, nil
}
