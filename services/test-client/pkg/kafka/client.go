package kafka

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	kafkago "github.com/segmentio/kafka-go"
	"github.com/segmentio/kafka-go/sasl"
	"go.uber.org/zap"
)

// ---------------------------------------------------------------------------
// SASL/OAUTHBEARER mechanism implementation
// ---------------------------------------------------------------------------

// OAuthBearerMechanism implements sasl.Mechanism for OAUTHBEARER.
// kafka-go does not ship a built-in OAUTHBEARER implementation, so we provide
// one that follows the OAUTHBEARER initial client response format defined in
// RFC 7628 and Kafka protocol extension KIP-255.
type OAuthBearerMechanism struct {
	Token string
}

var _ sasl.Mechanism = OAuthBearerMechanism{}

// Name returns the SASL mechanism name registered with the Kafka broker.
func (m OAuthBearerMechanism) Name() string { return "OAUTHBEARER" }

// Start produces the initial SASL client response.
// Format (GS2 + OAUTHBEARER extension):
//
//	n,,\x01auth=Bearer <token>\x01\x01
func (m OAuthBearerMechanism) Start(_ context.Context) (mechanism string, initialResponse []byte, err error) {
	authData := fmt.Sprintf("n,,\x01auth=Bearer %s\x01\x01", m.Token)
	return "OAUTHBEARER", []byte(authData), nil
}

// Next handles server challenges.  OAUTHBEARER has no additional round-trips
// after the initial response if the token is accepted; an error challenge from
// the broker is handled by the connection layer.
func (m OAuthBearerMechanism) Next(_ context.Context, _ []byte) (done bool, response []byte, err error) {
	return true, nil, nil
}

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

// Config holds all parameters required to connect to the Kafka cluster.
type Config struct {
	// Bootstrap is the broker address, e.g. "kafka:9093".
	Bootstrap string

	// SecurityProto is one of "SASL_SSL" or "PLAINTEXT".
	SecurityProto string

	// SASLMechanism should be "OAUTHBEARER" (or empty for PLAINTEXT).
	SASLMechanism string

	// OAuthToken is the raw JWT access token for SASL/OAUTHBEARER auth.
	OAuthToken string

	// CAcertPath is the path to the PEM-encoded CA certificate used when
	// SecurityProto is SASL_SSL.  Leave empty to use the system cert pool.
	CAcertPath string

	// TenantID is informational – used for log fields.
	TenantID string
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

// Client wraps kafka-go primitives and owns the TLS / SASL configuration.
type Client struct {
	config *Config
	logger *zap.Logger
}

// NewClient creates a new Kafka Client from cfg.  Logger must not be nil.
func NewClient(cfg *Config, logger *zap.Logger) *Client {
	return &Client{config: cfg, logger: logger}
}

// ProduceMessage writes a single key/value message to topic.
// The writer is created and closed per call so that each invocation uses a
// fresh authentication token (important when tokens have short lifetimes).
func (c *Client) ProduceMessage(ctx context.Context, topic, key, value string) error {
	transport, err := c.buildTransport()
	if err != nil {
		return fmt.Errorf("kafka: build transport: %w", err)
	}

	writer := &kafkago.Writer{
		Addr:         kafkago.TCP(c.config.Bootstrap),
		Topic:        topic,
		Balancer:     &kafkago.LeastBytes{},
		Transport:    transport,
		WriteTimeout: 10 * time.Second,
	}
	defer writer.Close()

	c.logger.Info("producing message",
		zap.String("topic", topic),
		zap.String("tenant_id", c.config.TenantID),
		zap.String("key", key),
	)

	if err := writer.WriteMessages(ctx, kafkago.Message{
		Key:   []byte(key),
		Value: []byte(value),
	}); err != nil {
		return fmt.Errorf("kafka: write to %s: %w", topic, err)
	}

	c.logger.Info("message produced successfully",
		zap.String("topic", topic),
		zap.String("key", key),
	)
	return nil
}

// ConsumeMessages reads up to count messages from topic using the given
// consumer groupID.  It returns as many messages as it received before the
// context is cancelled or count is reached.
func (c *Client) ConsumeMessages(ctx context.Context, topic, groupID string, count int) ([]string, error) {
	dialer, err := c.buildDialer()
	if err != nil {
		return nil, fmt.Errorf("kafka: build dialer: %w", err)
	}

	reader := kafkago.NewReader(kafkago.ReaderConfig{
		Brokers:     []string{c.config.Bootstrap},
		Topic:       topic,
		GroupID:     groupID,
		Dialer:      dialer,
		StartOffset: kafkago.FirstOffset,
		MaxWait:     5 * time.Second,
	})
	defer reader.Close()

	c.logger.Info("consuming messages",
		zap.String("topic", topic),
		zap.String("group_id", groupID),
		zap.Int("count", count),
	)

	messages := make([]string, 0, count)
	for i := 0; i < count; i++ {
		msg, err := reader.ReadMessage(ctx)
		if err != nil {
			c.logger.Warn("read message error",
				zap.String("topic", topic),
				zap.Error(err),
			)
			break
		}
		messages = append(messages, string(msg.Value))
		c.logger.Debug("received message",
			zap.String("topic", topic),
			zap.String("value", string(msg.Value)),
		)
	}

	c.logger.Info("consumed messages",
		zap.String("topic", topic),
		zap.Int("received", len(messages)),
	)
	return messages, nil
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// buildTLSConfig creates a *tls.Config.  If CAcertPath is set the named file
// is loaded as the only trusted CA (useful for self-signed certs in Docker).
// Otherwise the system certificate pool is used.
func (c *Client) buildTLSConfig() (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if c.config.CAcertPath != "" {
		caPem, err := os.ReadFile(c.config.CAcertPath)
		if err != nil {
			return nil, fmt.Errorf("kafka: read CA cert %s: %w", c.config.CAcertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPem) {
			return nil, fmt.Errorf("kafka: failed to parse CA cert from %s", c.config.CAcertPath)
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}

// buildDialer returns a kafka-go Dialer configured for SASL/OAUTHBEARER or
// plain TLS, depending on Config.SecurityProto.
func (c *Client) buildDialer() (*kafkago.Dialer, error) {
	dialer := &kafkago.Dialer{
		Timeout:   10 * time.Second,
		DualStack: true,
	}

	if c.config.SecurityProto == "SASL_SSL" {
		tlsCfg, err := c.buildTLSConfig()
		if err != nil {
			return nil, err
		}
		dialer.TLS = tlsCfg
		dialer.SASLMechanism = OAuthBearerMechanism{Token: c.config.OAuthToken}
	}

	return dialer, nil
}

// buildTransport returns a kafka-go Transport for the Writer path.
func (c *Client) buildTransport() (*kafkago.Transport, error) {
	transport := &kafkago.Transport{
		DialTimeout: 10 * time.Second,
	}

	if c.config.SecurityProto == "SASL_SSL" {
		tlsCfg, err := c.buildTLSConfig()
		if err != nil {
			return nil, err
		}
		transport.TLS = tlsCfg
		transport.SASL = OAuthBearerMechanism{Token: c.config.OAuthToken}
	}

	return transport, nil
}
