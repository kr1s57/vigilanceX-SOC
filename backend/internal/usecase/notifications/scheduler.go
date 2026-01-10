package notifications

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// ReportDataProvider provides data for scheduled reports
type ReportDataProvider interface {
	GetDailyReportData(ctx context.Context) (*entity.ReportData, error)
	GetWeeklyReportData(ctx context.Context) (*entity.ReportData, error)
	GetMonthlyReportData(ctx context.Context) (*entity.ReportData, error)
}

// Scheduler handles scheduled report sending
type Scheduler struct {
	service      *Service
	dataProvider ReportDataProvider
	logger       *slog.Logger

	// Timers for scheduled reports
	dailyTimer   *time.Timer
	weeklyTimer  *time.Timer
	monthlyTimer *time.Timer

	// Stop channel
	stopCh chan struct{}
	mu     sync.Mutex
}

// NewScheduler creates a new scheduler
func NewScheduler(service *Service, dataProvider ReportDataProvider, logger *slog.Logger) *Scheduler {
	s := &Scheduler{
		service:      service,
		dataProvider: dataProvider,
		logger:       logger,
		stopCh:       make(chan struct{}),
	}

	return s
}

// Start starts the scheduler with current settings
func (s *Scheduler) Start() {
	settings := s.service.GetSettings()
	s.RescheduleReports(settings)
	s.logger.Info("Notification scheduler started")
}

// Stop stops the scheduler
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	close(s.stopCh)

	if s.dailyTimer != nil {
		s.dailyTimer.Stop()
	}
	if s.weeklyTimer != nil {
		s.weeklyTimer.Stop()
	}
	if s.monthlyTimer != nil {
		s.monthlyTimer.Stop()
	}

	s.logger.Info("Notification scheduler stopped")
}

// RescheduleReports reschedules all reports based on settings
func (s *Scheduler) RescheduleReports(settings *entity.NotificationSettings) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stop existing timers
	if s.dailyTimer != nil {
		s.dailyTimer.Stop()
	}
	if s.weeklyTimer != nil {
		s.weeklyTimer.Stop()
	}
	if s.monthlyTimer != nil {
		s.monthlyTimer.Stop()
	}

	// Schedule daily report
	if settings.DailyReportEnabled {
		s.scheduleDailyReport(settings.DailyReportTime)
	}

	// Schedule weekly report
	if settings.WeeklyReportEnabled {
		s.scheduleWeeklyReport(settings.WeeklyReportDay, settings.WeeklyReportTime)
	}

	// Schedule monthly report
	if settings.MonthlyReportEnabled {
		s.scheduleMonthlyReport(settings.MonthlyReportDay, settings.MonthlyReportTime)
	}
}

// scheduleDailyReport schedules the daily report
func (s *Scheduler) scheduleDailyReport(timeStr string) {
	nextTime := s.getNextDailyTime(timeStr)
	duration := time.Until(nextTime)

	s.logger.Info("Scheduled daily report", "next_run", nextTime, "in", duration)

	s.dailyTimer = time.AfterFunc(duration, func() {
		s.runDailyReport()
		// Reschedule for next day
		settings := s.service.GetSettings()
		if settings.DailyReportEnabled {
			s.mu.Lock()
			s.scheduleDailyReport(settings.DailyReportTime)
			s.mu.Unlock()
		}
	})
}

// scheduleWeeklyReport schedules the weekly report
func (s *Scheduler) scheduleWeeklyReport(dayOfWeek int, timeStr string) {
	nextTime := s.getNextWeeklyTime(dayOfWeek, timeStr)
	duration := time.Until(nextTime)

	s.logger.Info("Scheduled weekly report", "next_run", nextTime, "in", duration)

	s.weeklyTimer = time.AfterFunc(duration, func() {
		s.runWeeklyReport()
		// Reschedule for next week
		settings := s.service.GetSettings()
		if settings.WeeklyReportEnabled {
			s.mu.Lock()
			s.scheduleWeeklyReport(settings.WeeklyReportDay, settings.WeeklyReportTime)
			s.mu.Unlock()
		}
	})
}

// scheduleMonthlyReport schedules the monthly report
func (s *Scheduler) scheduleMonthlyReport(dayOfMonth int, timeStr string) {
	nextTime := s.getNextMonthlyTime(dayOfMonth, timeStr)
	duration := time.Until(nextTime)

	s.logger.Info("Scheduled monthly report", "next_run", nextTime, "in", duration)

	s.monthlyTimer = time.AfterFunc(duration, func() {
		s.runMonthlyReport()
		// Reschedule for next month
		settings := s.service.GetSettings()
		if settings.MonthlyReportEnabled {
			s.mu.Lock()
			s.scheduleMonthlyReport(settings.MonthlyReportDay, settings.MonthlyReportTime)
			s.mu.Unlock()
		}
	})
}

// runDailyReport executes the daily report
func (s *Scheduler) runDailyReport() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	s.logger.Info("Running daily report")

	var data *entity.ReportData
	var err error

	if s.dataProvider != nil {
		data, err = s.dataProvider.GetDailyReportData(ctx)
		if err != nil {
			s.logger.Error("Failed to get daily report data", "error", err)
			return
		}
	} else {
		// Use empty data if no provider
		data = &entity.ReportData{
			Period:    "daily",
			StartDate: time.Now().Add(-24 * time.Hour),
			EndDate:   time.Now(),
		}
	}

	if err := s.service.SendDailyReport(ctx, data); err != nil {
		s.logger.Error("Failed to send daily report", "error", err)
	}
}

// runWeeklyReport executes the weekly report
func (s *Scheduler) runWeeklyReport() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	s.logger.Info("Running weekly report")

	var data *entity.ReportData
	var err error

	if s.dataProvider != nil {
		data, err = s.dataProvider.GetWeeklyReportData(ctx)
		if err != nil {
			s.logger.Error("Failed to get weekly report data", "error", err)
			return
		}
	} else {
		data = &entity.ReportData{
			Period:    "weekly",
			StartDate: time.Now().Add(-7 * 24 * time.Hour),
			EndDate:   time.Now(),
		}
	}

	if err := s.service.SendWeeklyReport(ctx, data); err != nil {
		s.logger.Error("Failed to send weekly report", "error", err)
	}
}

// runMonthlyReport executes the monthly report
func (s *Scheduler) runMonthlyReport() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	s.logger.Info("Running monthly report")

	var data *entity.ReportData
	var err error

	if s.dataProvider != nil {
		data, err = s.dataProvider.GetMonthlyReportData(ctx)
		if err != nil {
			s.logger.Error("Failed to get monthly report data", "error", err)
			return
		}
	} else {
		data = &entity.ReportData{
			Period:    "monthly",
			StartDate: time.Now().Add(-30 * 24 * time.Hour),
			EndDate:   time.Now(),
		}
	}

	if err := s.service.SendMonthlyReport(ctx, data); err != nil {
		s.logger.Error("Failed to send monthly report", "error", err)
	}
}

// getNextDailyTime calculates the next daily report time
func (s *Scheduler) getNextDailyTime(timeStr string) time.Time {
	hour, minute := parseTimeString(timeStr)
	now := time.Now()

	next := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())

	// If the time has passed today, schedule for tomorrow
	if next.Before(now) {
		next = next.Add(24 * time.Hour)
	}

	return next
}

// getNextWeeklyTime calculates the next weekly report time
func (s *Scheduler) getNextWeeklyTime(dayOfWeek int, timeStr string) time.Time {
	hour, minute := parseTimeString(timeStr)
	now := time.Now()

	// Find next occurrence of the day
	daysUntil := (dayOfWeek - int(now.Weekday()) + 7) % 7
	if daysUntil == 0 {
		// Check if time has passed today
		todayTime := time.Date(now.Year(), now.Month(), now.Day(), hour, minute, 0, 0, now.Location())
		if todayTime.Before(now) {
			daysUntil = 7
		}
	}

	next := time.Date(now.Year(), now.Month(), now.Day()+daysUntil, hour, minute, 0, 0, now.Location())
	return next
}

// getNextMonthlyTime calculates the next monthly report time
func (s *Scheduler) getNextMonthlyTime(dayOfMonth int, timeStr string) time.Time {
	hour, minute := parseTimeString(timeStr)
	now := time.Now()

	// Clamp day to valid range
	if dayOfMonth < 1 {
		dayOfMonth = 1
	} else if dayOfMonth > 28 {
		dayOfMonth = 28
	}

	next := time.Date(now.Year(), now.Month(), dayOfMonth, hour, minute, 0, 0, now.Location())

	// If the date has passed this month, schedule for next month
	if next.Before(now) {
		next = next.AddDate(0, 1, 0)
	}

	return next
}

// parseTimeString parses a time string in HH:MM format
func parseTimeString(timeStr string) (hour, minute int) {
	hour = 8
	minute = 0

	if len(timeStr) >= 5 {
		t, err := time.Parse("15:04", timeStr)
		if err == nil {
			return t.Hour(), t.Minute()
		}
	}

	return hour, minute
}
