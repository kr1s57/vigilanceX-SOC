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

	// Create connection with timeout
	dialer := net.Dialer{Timeout: c.config.Timeout}

	var conn net.Conn
	var err error

	switch strings.ToLower(c.config.Security) {
	case "ssl":
		// Direct TLS connection (port 465)
		tlsConfig := &tls.Config{
			ServerName: c.config.Host,
		}
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, tlsConfig)
	default:
		// Plain connection first, then STARTTLS
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

	// STARTTLS if using TLS mode (port 587)
	if strings.ToLower(c.config.Security) == "tls" {
		tlsConfig := &tls.Config{
			ServerName: c.config.Host,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	// Authenticate
	auth := smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.Host)
	if err := client.Auth(auth); err != nil {
		// Try LOGIN auth for servers that don't support PLAIN
		auth = LoginAuth(c.config.Username, c.config.Password)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
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

	// Create connection with timeout
	dialer := net.Dialer{Timeout: c.config.Timeout}

	var conn net.Conn
	var err error

	switch strings.ToLower(c.config.Security) {
	case "ssl":
		tlsConfig := &tls.Config{
			ServerName: c.config.Host,
		}
		conn, err = tls.DialWithDialer(&dialer, "tcp", addr, tlsConfig)
	default:
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

	// STARTTLS if using TLS mode
	if strings.ToLower(c.config.Security) == "tls" {
		tlsConfig := &tls.Config{
			ServerName: c.config.Host,
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	// Authenticate
	auth := smtp.PlainAuth("", c.config.Username, c.config.Password, c.config.Host)
	if err := client.Auth(auth); err != nil {
		auth = LoginAuth(c.config.Username, c.config.Password)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("authentication failed: %w", err)
		}
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
