package app

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyAllowsTheProviderOrigin(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("page"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler, err := webHandler(directory, "https://id.example.test/realms/dataguard")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/catalog", nil))

	policy := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(policy, "connect-src 'self' https://id.example.test;") {
		t.Fatalf("policy = %s", policy)
	}
	if recorder.Body.String() != "page" {
		t.Fatal("unknown paths must serve the page for client routing")
	}
}

func TestPathTraversalStaysInTheDirectory(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("page"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler, err := webHandler(directory, "https://id.example.test")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(directory, "escape")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/../../etc/passwd", "/escape/passwd"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.URL.Path = target
		handler.ServeHTTP(recorder, request)
		if strings.Contains(recorder.Body.String(), "root:") {
			t.Fatalf("%s: served a file outside the directory", target)
		}
	}
	recorder := httptest.NewRecorder()
	_ = recorder
}
