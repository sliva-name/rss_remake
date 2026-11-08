package main

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// secret returns a secret setting. NAME_FILE names a file that holds it, which is
// how container secrets arrive and keeps the value out of the Docker API; NAME
// holds it directly. Both at once are refused, so a variable left over from an
// older setup cannot silently win over the file.
func secret(name string) (string, error) {
	path, direct := os.Getenv(name+"_FILE"), os.Getenv(name)
	switch {
	case path != "" && direct != "":
		return "", fmt.Errorf("%s and %s_FILE are both set, keep one", name, name)
	case path == "":
		return direct, nil
	}
	content, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // The operator chooses this path in the server's configuration.
	if err != nil {
		return "", fmt.Errorf("%s_FILE: %w", name, err)
	}
	value := strings.TrimRight(string(content), "\r\n")
	if value == "" {
		return "", fmt.Errorf("%s_FILE: file is empty", name)
	}
	return value, nil
}

func mustSecret(name string) string {
	value, err := secret(name)
	if err == nil && value == "" {
		err = fmt.Errorf("%s or %s_FILE is required", name, name)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "dataguard-server:", err)
		os.Exit(1)
	}
	return value
}

// postgresDSN reads a connection string from dsnName and, when passwordName is
// set either way, puts that password into it. The address then stays in plain
// configuration and only the password lives in a secret file.
func postgresDSN(dsnName, passwordName string) (string, error) {
	dsn := os.Getenv(dsnName)
	if dsn == "" {
		return "", fmt.Errorf("%s is required", dsnName)
	}
	password, err := secret(passwordName)
	if err != nil || password == "" {
		return dsn, err
	}
	return withPassword(dsn, password)
}

func withPassword(dsn, password string) (string, error) {
	parsed, err := url.Parse(dsn)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") {
		// The parse error would repeat the connection string.
		return "", errors.New("with a separate password the connection string must be a postgres:// URL")
	}
	if parsed.User == nil {
		return "", errors.New("the connection string names no user")
	}
	if _, set := parsed.User.Password(); set {
		return "", errors.New("the connection string already has a password")
	}
	parsed.User = url.UserPassword(parsed.User.Username(), password)
	return parsed.String(), nil
}

func mustPostgresDSN(dsnName, passwordName string) string {
	dsn, err := postgresDSN(dsnName, passwordName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dataguard-server: %s: %v\n", dsnName, err)
		os.Exit(1)
	}
	return dsn
}
