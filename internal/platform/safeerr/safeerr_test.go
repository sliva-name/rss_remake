package safeerr_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"dataguard/internal/platform/safeerr"
)

func TestNewDropsCauseText(t *testing.T) {
	cause := errors.New(`duplicate key: Key (email)=(canary.subject@dataguard.invalid) already exists`)
	err := fmt.Errorf("scan: %w", safeerr.New("profile column", safeerr.CodeQuery, cause))

	for _, rendered := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(rendered, "canary") {
			t.Fatalf("cause text leaked: %s", rendered)
		}
	}
	if got := safeerr.CodeOf(err); got != safeerr.CodeQuery {
		t.Fatalf("CodeOf = %s", got)
	}
}

func TestNewClassifiesContextErrors(t *testing.T) {
	wrapped := fmt.Errorf("query: %w", context.DeadlineExceeded)
	if got := safeerr.New("op", safeerr.CodeQuery, wrapped).Code; got != safeerr.CodeTimeout {
		t.Fatalf("code = %s", got)
	}
	if got := safeerr.New("op", safeerr.CodeQuery, context.Canceled).Code; got != safeerr.CodeCanceled {
		t.Fatalf("code = %s", got)
	}
}

func TestCodeOfForeignError(t *testing.T) {
	if got := safeerr.CodeOf(errors.New("x")); got != safeerr.CodeUnknown {
		t.Fatalf("code = %s", got)
	}
}
