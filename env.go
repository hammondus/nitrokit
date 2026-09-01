package nitrokit

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// EnvOr returns the value of the environment variable key, or fallback
// when the variable is unset or empty. Empty counts as unset because a
// docker-compose file with `FOO=` sets the variable to nothing, and no
// consumer has ever meant that.
func EnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// EnvInt is EnvOr for integers. A set-but-unparsable value is an error
// naming the variable, so a config typo fails at startup instead of
// silently running with the fallback.
func EnvInt(key string, fallback int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

// EnvFloat is EnvOr for floating-point numbers.
func EnvFloat(key string, fallback float64) (float64, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return f, nil
}

// EnvBool is EnvOr for booleans, accepting the strconv.ParseBool forms
// (1, t, true, 0, f, false, in any case).
func EnvBool(key string, fallback bool) (bool, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false, fmt.Errorf("%s: %w", key, err)
	}
	return b, nil
}

// EnvDuration is EnvOr for durations, in time.ParseDuration form
// ("90s", "15m", "1h30m").
func EnvDuration(key string, fallback time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
