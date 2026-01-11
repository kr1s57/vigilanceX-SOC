package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/kr1s57/vigilancex/internal/entity"
)

// Client handles SMTP email sending
type Client struct {
	config *Config
	logger *slog.Logger
}

// Config holds SMTP client configuration
type Config struct {
	Host       string
	Port       int
	Security   string // tls, ssl, none
	FromEmail  string
	Username   string
	Password   string
	Recipients []string
	Timeout    time.Duration
}

// NewClient creates a new SMTP client
func NewClient(cfg Config, logger *slog.Logger) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.Security == "" {
		cfg.Security = "tls"
	}
	return &Client{
		config: &cfg,
		logger: logger,
	}
}

// TestConnection tests the SMTP connection
func (c *Client) TestConnection(ctx context.Context) error {
	if c.config.Host == "" {
		return fmt.Errorf("SMTP host not configured")
	}
	if c.config.Username == "" {
		return fmt.Errorf("SMTP username not configured")
	}

	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	security := strings.ToLower(c.config.Security)

	c.logger.Info("Testing SMTP connection", "host", c.config.Host, "port", c.config.Port, "security", security)

	// Create connection with timeout
	dialer := net.Dialer{Timeout: c.config.Timeout}

	var conn net.Conn
	var err error

	switch security {
	case "ssl", "implicit":
		// Direct TLS connection (port 465)
		tlsConfig := &tls.Config{
			ServerName: c.config.Host,
		}
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, tlsConfig)
	case "none", "plain":
		// Plain connection, no TLS
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	default:
		// "tls", "starttls", or default: Plain connection first, then STARTTLS
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer conn.Close()

	// Create SMTP client
	client, err := smtp.NewClient(conn, c.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	// STARTTLS for tls/starttls modes (port 587)
	if security == "tls" || security == "starttls" || security == "" {
		// Check if server supports STARTTLS
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				ServerName: c.config.Host,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS failed: %w", err)
			}
			c.logger.Info("STARTTLS negotiated successfully")
		} else if security == "starttls" {
			return fmt.Errorf("server does not support STARTTLS")
		}
	}

	// Authenticate - try LOGIN first (Office365 requires it), then PLAIN
	var authErr error

	// Check supported auth methods
	authSupported := false
	if ok, authMethods := client.Extension("AUTH"); ok {
		c.logger.Debug("Server auth methods", "methods", authMethods)
		// Try LOGIN first (required for Office365)
		if strings.Contains(authMethods, "LOGIN") {
			auth := LoginAuth(c.config.Username, c.config.Password)
			if err := client.Auth(auth); err != nil {
				c.logger.Debug("LOGIN auth failed", "error", err)
				authErr = err
			} else {
				authSupported = true
			}
		}
		// Try PLAIN if LOGIN didn't work or isn't supported
		if !authSupported && strings.Contains(authMethods, "PLAIN") {
			auth := smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.Host)
			if err := client.Auth(auth); err != nil {
				c.logger.Debug("PLAIN auth failed", "error", err)
				authErr = err
			} else {
				authSupported = true
			}
		}
	}

	if !authSupported {
		if authErr != nil {
			return fmt.Errorf("authentication failed: %w", authErr)
		}
		return fmt.Errorf("no supported authentication method")
	}

	c.logger.Info("SMTP connection test successful", "host", c.config.Host, "port", c.config.Port)
	return nil
}

// SendEmail sends an email notification
func (c *Client) SendEmail(ctx context.Context, notif *entity.EmailNotification) error {
	if c.config.Host == "" {
		return fmt.Errorf("SMTP not configured")
	}

	recipients := notif.Recipients
	if len(recipients) == 0 {
		recipients = c.config.Recipients
	}
	if len(recipients) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	// Build email message
	msg := c.buildMessage(notif.Subject, notif.TextBody, notif.HTMLBody, recipients)

	addr := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)
	security := strings.ToLower(c.config.Security)

	// Create connection with timeout
	dialer := net.Dialer{Timeout: c.config.Timeout}

	var conn net.Conn
	var err error

	switch security {
	case "ssl", "implicit":
		tlsConfig := &tls.Config{
			ServerName: c.config.Host,
		}
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, tlsConfig)
	case "none", "plain":
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	default:
		// "tls", "starttls", or default
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, c.config.Host)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	// STARTTLS for tls/starttls modes
	if security == "tls" || security == "starttls" || security == "" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsConfig := &tls.Config{
				ServerName: c.config.Host,
			}
			if err := client.StartTLS(tlsConfig); err != nil {
				return fmt.Errorf("STARTTLS failed: %w", err)
			}
		} else if security == "starttls" {
			return fmt.Errorf("server does not support STARTTLS")
		}
	}

	// Authenticate - try LOGIN first (Office365 requires it), then PLAIN
	var authErr error
	authSupported := false

	if ok, authMethods := client.Extension("AUTH"); ok {
		c.logger.Debug("Server auth methods", "methods", authMethods)
		// Try LOGIN first (required for Office365)
		if strings.Contains(authMethods, "LOGIN") {
			auth := LoginAuth(c.config.Username, c.config.Password)
			if err := client.Auth(auth); err != nil {
				c.logger.Debug("LOGIN auth failed", "error", err)
				authErr = err
			} else {
				authSupported = true
			}
		}
		// Try PLAIN if LOGIN didn't work or isn't supported
		if !authSupported && strings.Contains(authMethods, "PLAIN") {
			auth := smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.Host)
			if err := client.Auth(auth); err != nil {
				c.logger.Debug("PLAIN auth failed", "error", err)
				authErr = err
			} else {
				authSupported = true
			}
		}
	}

	if !authSupported {
		if authErr != nil {
			return fmt.Errorf("authentication failed: %w", authErr)
		}
		return fmt.Errorf("no supported authentication method")
	}

	// Set sender
	if err := client.Mail(c.config.FromEmail); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	for _, rcpt := range recipients {
		if err := client.Rcpt(strings.TrimSpace(rcpt)); err != nil {
			return fmt.Errorf("failed to add recipient %s: %w", rcpt, err)
		}
	}

	// Send message
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}

	_, err = wc.Write(msg)
	if err != nil {
		wc.Close()
		return fmt.Errorf("failed to write message: %w", err)
	}

	if err := wc.Close(); err != nil {
		return fmt.Errorf("failed to close data writer: %w", err)
	}

	c.logger.Info("Email sent successfully",
		"subject", notif.Subject,
		"recipients", len(recipients),
		"type", notif.Type,
	)

	return client.Quit()
}

// buildMessage builds a MIME email message
func (c *Client) buildMessage(subject, textBody, htmlBody string, recipients []string) []byte {
	boundary := "==VIGILANCEX_BOUNDARY=="

	var msg strings.Builder

	// Headers
	msg.WriteString(fmt.Sprintf("From: VIGILANCE X <%s>\r\n", c.config.FromEmail))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(recipients, ", ")))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msg.WriteString("MIME-Version: 1.0\r\n")

	if htmlBody != "" {
		// Multipart message with text and HTML
		msg.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", boundary))
		msg.WriteString("\r\n")

		// Text part
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
		msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(textBody)
		msg.WriteString("\r\n")

		// HTML part
		msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		msg.WriteString("Content-Type: text/html; charset=\"UTF-8\"\r\n")
		msg.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(htmlBody)
		msg.WriteString("\r\n")

		msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Plain text only
		msg.WriteString("Content-Type: text/plain; charset=\"UTF-8\"\r\n")
		msg.WriteString("\r\n")
		msg.WriteString(textBody)
	}

	return []byte(msg.String())
}

// IsConfigured returns true if SMTP is configured
func (c *Client) IsConfigured() bool {
	return c.config != nil && c.config.Host != "" && c.config.Username != ""
}

// GetHost returns the SMTP host
func (c *Client) GetHost() string {
	if c.config == nil {
		return ""
	}
	return c.config.Host
}

// GetRecipients returns the default recipients
func (c *Client) GetRecipients() []string {
	if c.config == nil {
		return nil
	}
	return c.config.Recipients
}

// LoginAuth implements the LOGIN authentication mechanism
type loginAuth struct {
	username, password string
}

// LoginAuth returns an Auth that implements the LOGIN authentication
func LoginAuth(username, password string) smtp.Auth {
	return &loginAuth{username, password}
}

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", []byte{}, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(a.username), nil
		case "Password:":
			return []byte(a.password), nil
		default:
			return nil, fmt.Errorf("unknown server challenge: %s", fromServer)
		}
	}
	return nil, nil
}
