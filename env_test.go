package nitrokit_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hammondus/nitrokit"
)

func TestEnvOr(t *testing.T) {
	t.Setenv("NK_SET", "value")
	t.Setenv("NK_EMPTY", "")
	if got := nitrokit.EnvOr("NK_SET", "fb"); got != "value" {
		t.Errorf("set: got %q", got)
	}
	if got := nitrokit.EnvOr("NK_EMPTY", "fb"); got != "fb" {
		t.Errorf("empty: got %q, want fallback", got)
	}
	if got := nitrokit.EnvOr("NK_UNSET", "fb"); got != "fb" {
		t.Errorf("unset: got %q, want fallback", got)
	}
}

func TestEnvTyped(t *testing.T) {
	t.Setenv("NK_INT", "42")
	t.Setenv("NK_FLOAT", "2.5")
	t.Setenv("NK_BOOL", "true")
	t.Setenv("NK_DUR", "90s")
	t.Setenv("NK_BAD", "rubbish")

	if n, err := nitrokit.EnvInt("NK_INT", 1); err != nil || n != 42 {
		t.Errorf("EnvInt = %d, %v", n, err)
	}
	if n, err := nitrokit.EnvInt("NK_UNSET", 7); err != nil || n != 7 {
		t.Errorf("EnvInt fallback = %d, %v", n, err)
	}
	if f, err := nitrokit.EnvFloat("NK_FLOAT", 1); err != nil || f != 2.5 {
		t.Errorf("EnvFloat = %g, %v", f, err)
	}
	if b, err := nitrokit.EnvBool("NK_BOOL", false); err != nil || !b {
		t.Errorf("EnvBool = %v, %v", b, err)
	}
	if d, err := nitrokit.EnvDuration("NK_DUR", time.Second); err != nil || d != 90*time.Second {
		t.Errorf("EnvDuration = %v, %v", d, err)
	}

	if _, err := nitrokit.EnvInt("NK_BAD", 1); err == nil || !strings.Contains(err.Error(), "NK_BAD") {
		t.Errorf("EnvInt bad value: err = %v, want error naming NK_BAD", err)
	}
	if _, err := nitrokit.EnvFloat("NK_BAD", 1); err == nil {
		t.Error("EnvFloat accepted rubbish")
	}
	if _, err := nitrokit.EnvBool("NK_BAD", false); err == nil {
		t.Error("EnvBool accepted rubbish")
	}
	if _, err := nitrokit.EnvDuration("NK_BAD", time.Second); err == nil {
		t.Error("EnvDuration accepted rubbish")
	}
}
