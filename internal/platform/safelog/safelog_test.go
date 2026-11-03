package safelog_test

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"dataguard/internal/platform/safeerr"
	"dataguard/internal/platform/safelog"
)

const canary = "canary.subject@dataguard.invalid"

func TestUnknownAttributesAreRedacted(t *testing.T) {
	var buffer bytes.Buffer
	logger := safelog.New(&buffer, slog.LevelInfo)

	logger.Info("query seen", "query", "SELECT 1 WHERE email = '"+canary+"'", "source_key", "crm")

	out := buffer.String()
	if strings.Contains(out, canary) {
		t.Fatalf("value leaked: %s", out)
	}
	if !strings.Contains(out, `"source_key":"crm"`) {
		t.Fatalf("allowed attribute lost: %s", out)
	}
}

func TestPlainErrorIsRedactedSafeErrorIsKept(t *testing.T) {
	var buffer bytes.Buffer
	logger := safelog.New(&buffer, slog.LevelInfo)

	logger.Error("failed", "error", errors.New("Key (email)=("+canary+") already exists"))
	logger.Error("failed", "error", safeerr.New("profile column", safeerr.CodeQuery, errors.New(canary)))

	out := buffer.String()
	if strings.Contains(out, canary) {
		t.Fatalf("value leaked: %s", out)
	}
	if !strings.Contains(out, "profile column: QUERY_FAILED") {
		t.Fatalf("safe error lost: %s", out)
	}
}

func TestNestedGroupsAreFiltered(t *testing.T) {
	var buffer bytes.Buffer
	logger := safelog.New(&buffer, slog.LevelInfo)

	logger.Info("nested", slog.Group("details", "msg", canary, "time", canary))

	if out := buffer.String(); strings.Contains(out, canary) {
		t.Fatalf("value leaked through group: %s", out)
	}
}
