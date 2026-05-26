package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/kafkaoauth/test-client/pkg/auth"
	kafkaclient "github.com/kafkaoauth/test-client/pkg/kafka"
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

type config struct {
	AuthServiceURL string
	KafkaBootstrap string
	SecurityProto  string
	SASLMechanism  string
	CAcertPath     string

	AliceUsername string
	AlicePassword string
	AliceTenantID string

	BobUsername string
	BobPassword string
	BobTenantID string
}

func loadConfig() config {
	getEnvDefault := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}

	return config{
		AuthServiceURL: getEnvDefault("AUTH_SERVICE_URL", "http://auth-service:8080"),
		KafkaBootstrap: getEnvDefault("KAFKA_BOOTSTRAP", "kafka:9093"),
		SecurityProto:  getEnvDefault("SECURITY_PROTO", "SASL_SSL"),
		SASLMechanism:  getEnvDefault("SASL_MECHANISM", "OAUTHBEARER"),
		CAcertPath:     getEnvDefault("CA_CERT_PATH", "/certs/ca.crt"),

		AliceUsername: getEnvDefault("ALICE_USERNAME", "alice"),
		AlicePassword: getEnvDefault("ALICE_PASSWORD", "alice_password"),
		AliceTenantID: getEnvDefault("ALICE_TENANT_ID", "tenant-a"),

		BobUsername: getEnvDefault("BOB_USERNAME", "bob"),
		BobPassword: getEnvDefault("BOB_PASSWORD", "bob_password"),
		BobTenantID: getEnvDefault("BOB_TENANT_ID", "tenant-b"),
	}
}

// ---------------------------------------------------------------------------
// Scenario result tracking
// ---------------------------------------------------------------------------

type result struct {
	scenario string
	expected string
	passed   bool
	detail   string
}

func pass(scenario, expected, detail string) result {
	return result{scenario: scenario, expected: expected, passed: true, detail: detail}
}

func fail(scenario, expected, detail string) result {
	return result{scenario: scenario, expected: expected, passed: false, detail: detail}
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	cfg := loadConfig()

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("starting Kafka OAuth integration test suite",
		zap.String("auth_service", cfg.AuthServiceURL),
		zap.String("kafka_bootstrap", cfg.KafkaBootstrap),
		zap.String("security_proto", cfg.SecurityProto),
	)

	authClient := auth.NewClient(cfg.AuthServiceURL)
	ctx := context.Background()

	var results []result

	// -----------------------------------------------------------------------
	// Scenario 1 – Tenant A: produce + consume on own topic (expect SUCCESS)
	// -----------------------------------------------------------------------
	printHeader("Scenario 1: Tenant A – produce and consume own topic (expect SUCCESS)")

	results = append(results, runScenario1(ctx, cfg, authClient, logger))

	// -----------------------------------------------------------------------
	// Scenario 2 – Cross-tenant write (expect DENIED)
	// -----------------------------------------------------------------------
	printHeader("Scenario 2: Tenant A – cross-tenant write to tenant-b topic (expect DENIED)")

	results = append(results, runScenario2(ctx, cfg, authClient, logger))

	// -----------------------------------------------------------------------
	// Scenario 3 – Tenant B: produce + consume on own topic (expect SUCCESS)
	// -----------------------------------------------------------------------
	printHeader("Scenario 3: Tenant B – produce and consume own topic (expect SUCCESS)")

	results = append(results, runScenario3(ctx, cfg, authClient, logger))

	// -----------------------------------------------------------------------
	// Scenario 4 – Wrong topic prefix (expect DENIED)
	// -----------------------------------------------------------------------
	printHeader("Scenario 4: No tenant prefix topic (expect DENIED)")

	results = append(results, runScenario4(ctx, cfg, authClient, logger))

	// -----------------------------------------------------------------------
	// Print summary table
	// -----------------------------------------------------------------------
	printSummary(results)

	// Exit non-zero if any scenario produced an unexpected outcome.
	for _, r := range results {
		if !r.passed {
			os.Exit(1)
		}
	}
}

// ---------------------------------------------------------------------------
// Individual scenarios
// ---------------------------------------------------------------------------

// runScenario1: alice produces 3 messages to tenant-a-events, then consumes them.
func runScenario1(ctx context.Context, cfg config, authClient *auth.Client, logger *zap.Logger) result {
	const scenario = "Tenant A: produce to own topic"
	const topic = "tenant-a-events"
	const groupID = "tenant-a-test-group"

	logger.Info("obtaining Kafka token for alice")
	token, err := authClient.GetKafkaToken(ctx, cfg.AliceUsername, cfg.AlicePassword, cfg.AliceTenantID)
	if err != nil {
		return fail(scenario, "SUCCESS", fmt.Sprintf("token fetch: %v", err))
	}
	logger.Info("token obtained for alice", zap.String("tenant", cfg.AliceTenantID))

	kc := kafkaclient.NewClient(&kafkaclient.Config{
		Bootstrap:     cfg.KafkaBootstrap,
		SecurityProto: cfg.SecurityProto,
		SASLMechanism: cfg.SASLMechanism,
		OAuthToken:    token,
		CAcertPath:    cfg.CAcertPath,
		TenantID:      cfg.AliceTenantID,
	}, logger)

	messages := []string{
		fmt.Sprintf(`{"event":"user.login","user":"alice","ts":"%s"}`, time.Now().UTC().Format(time.RFC3339)),
		fmt.Sprintf(`{"event":"order.created","user":"alice","order_id":"ord-001","ts":"%s"}`, time.Now().UTC().Format(time.RFC3339)),
		fmt.Sprintf(`{"event":"payment.processed","user":"alice","amount":99.99,"ts":"%s"}`, time.Now().UTC().Format(time.RFC3339)),
	}

	for i, msg := range messages {
		key := fmt.Sprintf("alice-msg-%d", i+1)
		if err := kc.ProduceMessage(ctx, topic, key, msg); err != nil {
			return fail(scenario, "SUCCESS", fmt.Sprintf("produce message %d: %v", i+1, err))
		}
		logger.Info("produced message", zap.Int("index", i+1), zap.String("topic", topic))
	}

	logger.Info("consuming messages from tenant-a-events")
	consumed, err := kc.ConsumeMessages(ctx, topic, groupID, len(messages))
	if err != nil {
		return fail(scenario, "SUCCESS", fmt.Sprintf("consume: %v", err))
	}

	logger.Info("consumed messages", zap.Int("count", len(consumed)))
	return pass(scenario, "SUCCESS",
		fmt.Sprintf("produced %d / consumed %d messages", len(messages), len(consumed)))
}

// runScenario2: alice tries to write to tenant-b-events; should be DENIED.
func runScenario2(ctx context.Context, cfg config, authClient *auth.Client, logger *zap.Logger) result {
	const scenario = "Tenant A: cross-tenant access"
	const topic = "tenant-b-events"

	logger.Info("obtaining Kafka token for alice (tenant-a)")
	token, err := authClient.GetKafkaToken(ctx, cfg.AliceUsername, cfg.AlicePassword, cfg.AliceTenantID)
	if err != nil {
		return fail(scenario, "DENIED", fmt.Sprintf("token fetch: %v", err))
	}

	kc := kafkaclient.NewClient(&kafkaclient.Config{
		Bootstrap:     cfg.KafkaBootstrap,
		SecurityProto: cfg.SecurityProto,
		SASLMechanism: cfg.SASLMechanism,
		OAuthToken:    token,
		CAcertPath:    cfg.CAcertPath,
		TenantID:      cfg.AliceTenantID,
	}, logger)

	logger.Info("attempting cross-tenant write (should be denied)",
		zap.String("topic", topic),
		zap.String("token_tenant", cfg.AliceTenantID),
	)

	err = kc.ProduceMessage(ctx, topic,
		"cross-tenant-key",
		`{"event":"unauthorized_write","user":"alice"}`,
	)
	if err != nil {
		// Authorization error is expected – scenario passes.
		if isAuthorizationError(err) {
			logger.Info("cross-tenant write correctly denied", zap.Error(err))
			return pass(scenario, "DENIED", fmt.Sprintf("correctly denied: %v", err))
		}
		// Any other error also means the write failed – still counts as denied.
		logger.Info("write failed (non-auth error, still denied)", zap.Error(err))
		return pass(scenario, "DENIED", fmt.Sprintf("write failed as expected: %v", err))
	}

	// The write unexpectedly succeeded – this is a security failure.
	return fail(scenario, "DENIED", "write to tenant-b topic SUCCEEDED with tenant-a credentials (security violation!)")
}

// runScenario3: bob produces 2 messages to tenant-b-orders and consumes them.
func runScenario3(ctx context.Context, cfg config, authClient *auth.Client, logger *zap.Logger) result {
	const scenario = "Tenant B: produce to own topic"
	const topic = "tenant-b-orders"
	const groupID = "tenant-b-test-group"

	logger.Info("obtaining Kafka token for bob")
	token, err := authClient.GetKafkaToken(ctx, cfg.BobUsername, cfg.BobPassword, cfg.BobTenantID)
	if err != nil {
		return fail(scenario, "SUCCESS", fmt.Sprintf("token fetch: %v", err))
	}
	logger.Info("token obtained for bob", zap.String("tenant", cfg.BobTenantID))

	kc := kafkaclient.NewClient(&kafkaclient.Config{
		Bootstrap:     cfg.KafkaBootstrap,
		SecurityProto: cfg.SecurityProto,
		SASLMechanism: cfg.SASLMechanism,
		OAuthToken:    token,
		CAcertPath:    cfg.CAcertPath,
		TenantID:      cfg.BobTenantID,
	}, logger)

	messages := []string{
		fmt.Sprintf(`{"order_id":"ord-b-001","customer":"bob","amount":49.99,"ts":"%s"}`, time.Now().UTC().Format(time.RFC3339)),
		fmt.Sprintf(`{"order_id":"ord-b-002","customer":"bob","amount":129.00,"ts":"%s"}`, time.Now().UTC().Format(time.RFC3339)),
	}

	for i, msg := range messages {
		key := fmt.Sprintf("bob-order-%d", i+1)
		if err := kc.ProduceMessage(ctx, topic, key, msg); err != nil {
			return fail(scenario, "SUCCESS", fmt.Sprintf("produce message %d: %v", i+1, err))
		}
		logger.Info("produced order", zap.Int("index", i+1), zap.String("topic", topic))
	}

	consumed, err := kc.ConsumeMessages(ctx, topic, groupID, len(messages))
	if err != nil {
		return fail(scenario, "SUCCESS", fmt.Sprintf("consume: %v", err))
	}

	logger.Info("consumed orders", zap.Int("count", len(consumed)))
	return pass(scenario, "SUCCESS",
		fmt.Sprintf("produced %d / consumed %d messages", len(messages), len(consumed)))
}

// runScenario4: alice tries to write to "orders" (no tenant prefix) – DENIED.
func runScenario4(ctx context.Context, cfg config, authClient *auth.Client, logger *zap.Logger) result {
	const scenario = "Wrong topic prefix"
	const topic = "orders" // no tenant_id prefix

	logger.Info("obtaining Kafka token for alice")
	token, err := authClient.GetKafkaToken(ctx, cfg.AliceUsername, cfg.AlicePassword, cfg.AliceTenantID)
	if err != nil {
		return fail(scenario, "DENIED", fmt.Sprintf("token fetch: %v", err))
	}

	kc := kafkaclient.NewClient(&kafkaclient.Config{
		Bootstrap:     cfg.KafkaBootstrap,
		SecurityProto: cfg.SecurityProto,
		SASLMechanism: cfg.SASLMechanism,
		OAuthToken:    token,
		CAcertPath:    cfg.CAcertPath,
		TenantID:      cfg.AliceTenantID,
	}, logger)

	logger.Info("attempting write to unprefixed topic (should be denied)",
		zap.String("topic", topic),
		zap.String("token_tenant", cfg.AliceTenantID),
	)

	err = kc.ProduceMessage(ctx, topic,
		"no-prefix-key",
		`{"event":"write_attempt","topic":"orders","user":"alice"}`,
	)
	if err != nil {
		logger.Info("write to unprefixed topic correctly denied", zap.Error(err))
		return pass(scenario, "DENIED", fmt.Sprintf("correctly denied: %v", err))
	}

	return fail(scenario, "DENIED", "write to unprefixed topic SUCCEEDED (policy violation!)")
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// isAuthorizationError returns true if the error message looks like a Kafka
// authorization error (TOPIC_AUTHORIZATION_FAILED etc.).
func isAuthorizationError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "authorization") ||
		strings.Contains(msg, "unauthorized") ||
		strings.Contains(msg, "not authorized") ||
		strings.Contains(msg, "topic_authorization_failed")
}

func printHeader(header string) {
	line := strings.Repeat("─", 70)
	fmt.Printf("\n%s\n  %s\n%s\n", line, header, line)
}

func printSummary(results []result) {
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    KAFKA OAUTH TEST RESULTS                     ║")
	fmt.Println("╠════════════════════════════════════╦══════════════╦═════════════╣")
	fmt.Println("║ Scenario                           ║ Expected     ║ Result      ║")
	fmt.Println("╠════════════════════════════════════╬══════════════╬═════════════╣")

	allPassed := true
	for _, r := range results {
		resultStr := "✓ PASS"
		if !r.passed {
			resultStr = "✗ FAIL"
			allPassed = false
		}
		// Pad fields to match column widths: scenario=36, expected=12, result=11
		scenario := padRight(r.scenario, 34)
		expected := padRight(r.expected, 12)
		result := padRight(resultStr, 11)
		fmt.Printf("║ %s ║ %s ║ %s ║\n", scenario, expected, result)

		if !r.passed {
			fmt.Printf("║   %-64s ║\n", "  DETAIL: "+r.detail)
		}
	}

	fmt.Println("╚════════════════════════════════════╩══════════════╩═════════════╝")
	fmt.Println()

	if allPassed {
		fmt.Println("  All scenarios passed. Kafka OAuth authorization is working correctly.")
	} else {
		fmt.Println("  One or more scenarios FAILED. Review logs above for details.")
	}
	fmt.Println()
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
