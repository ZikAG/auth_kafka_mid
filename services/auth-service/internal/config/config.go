package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all runtime configuration for the auth-service.
type Config struct {
	Port                        string
	KeycloakURL                 string
	KeycloakRealm               string
	KeycloakClientID            string
	KeycloakClientSecret        string
	KafkaClientID               string
	KafkaClientSecret           string
	TokenExchangeTargetAudience string
	KafkaTokenLifetime          time.Duration
	RateLimitRPS                int
	LogLevel                    string
	Environment                 string
	EnableMetrics               bool

	// Computed from the above fields during Load.
	KeycloakTokenURL      string
	KeycloakIntrospectURL string
	KeycloakJWKSURL       string
	KeycloakUserInfoURL   string
}

// Load reads configuration from environment variables and applies defaults.
func Load() *Config {
	cfg := &Config{
		Port:                        getEnv("PORT", "8080"),
		KeycloakURL:                 getEnv("KEYCLOAK_URL", "http://keycloak:8080"),
		KeycloakRealm:               getEnv("KEYCLOAK_REALM", "kafka-realm"),
		KeycloakClientID:            getEnv("KEYCLOAK_CLIENT_ID", "auth-service"),
		KeycloakClientSecret:        getEnv("KEYCLOAK_CLIENT_SECRET", ""),
		KafkaClientID:               getEnv("KAFKA_CLIENT_ID", "kafka-client"),
		KafkaClientSecret:           getEnv("KAFKA_CLIENT_SECRET", ""),
		TokenExchangeTargetAudience: getEnv("TOKEN_EXCHANGE_TARGET_AUDIENCE", "kafka-broker"),
		KafkaTokenLifetime:          getEnvDuration("KAFKA_TOKEN_LIFETIME_SECONDS", 300) * time.Second,
		RateLimitRPS:                getEnvInt("RATE_LIMIT_RPS", 100),
		LogLevel:                    getEnv("LOG_LEVEL", "info"),
		Environment:                 getEnv("ENVIRONMENT", "production"),
		EnableMetrics:               getEnvBool("ENABLE_METRICS", true),
	}

	// Compute derived Keycloak endpoint URLs.
	realmBase := fmt.Sprintf("%s/realms/%s/protocol/openid-connect", cfg.KeycloakURL, cfg.KeycloakRealm)
	cfg.KeycloakTokenURL = realmBase + "/token"
	cfg.KeycloakIntrospectURL = realmBase + "/token/introspect"
	cfg.KeycloakJWKSURL = realmBase + "/certs"
	cfg.KeycloakUserInfoURL = realmBase + "/userinfo"

	return cfg
}

// getEnv returns the value of the named environment variable, or fallback if unset/empty.
func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvInt parses an integer environment variable.  Returns fallback on error.
func getEnvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// getEnvBool parses a boolean environment variable.  Returns fallback on error.
func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// getEnvDuration parses an integer environment variable as a number of seconds
// and returns it as a time.Duration in seconds (caller multiplies if needed).
func getEnvDuration(key string, fallbackSeconds int) time.Duration {
	return time.Duration(getEnvInt(key, fallbackSeconds))
}
