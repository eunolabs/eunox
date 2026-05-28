// Copyright 2026 Eunox Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
)

// auditRecord is an OCSF-inspired audit record written to the local audit log.
type auditRecord struct {
	ClassUID      int                    `json:"class_uid"`    // 6003 = API Activity
	CategoryUID   int                    `json:"category_uid"` // 6 = Application Activity
	ActivityID    int                    `json:"activity_id"`  // 1 = Allow, 2 = Deny
	Time          string                 `json:"time"`
	RequestID     string                 `json:"request_id"`
	SessionID     string                 `json:"session_id"`
	ToolName      string                 `json:"tool_name"`
	Decision      string                 `json:"decision"` // "allow" | "deny"
	DenialCode    string                 `json:"denial_code,omitempty"`
	ConditionType string                 `json:"condition_type,omitempty"`
	Details       map[string]interface{} `json:"details,omitempty"`
	Obligations   []string               `json:"obligations,omitempty"`
	HMAC          string                 `json:"_hmac,omitempty"`
}

// auditSink writes OCSF audit records to a JSONL file, signing each record
// with HMAC-SHA256 using a per-installation key.
type auditSink struct {
	mu       sync.Mutex
	f        *os.File
	key      []byte
	maxBytes int64
	written  int64
	logPath  string
}

const (
	defaultAuditLog       = "~/.eunox/audit.jsonl"
	defaultAuditKeyPath   = "~/.eunox/audit.key"
	defaultRotateSizeBytes = 100 << 20 // 100 MiB
)

// openAuditSink opens (or creates) the audit log and loads (or generates) the
// HMAC signing key.  logPath and rotateSizeBytes may be zero values for
// defaults.
func openAuditSink(logPath string, rotateSizeBytes int64) (*auditSink, error) {
	if logPath == "" {
		logPath = defaultAuditLog
	}
	logPath = expandHome(logPath)

	if rotateSizeBytes <= 0 {
		rotateSizeBytes = defaultRotateSizeBytes
	}

	key, err := loadOrCreateAuditKey(expandHome(defaultAuditKeyPath))
	if err != nil {
		return nil, fmt.Errorf("audit key: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0o700); err != nil {
		return nil, fmt.Errorf("creating audit log directory: %w", err)
	}

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // G304: path is user-configured audit log location
	if err != nil {
		return nil, fmt.Errorf("opening audit log %q: %w", logPath, err)
	}

	info, _ := f.Stat()
	var written int64
	if info != nil {
		written = info.Size()
	}

	return &auditSink{
		f:        f,
		key:      key,
		maxBytes: rotateSizeBytes,
		written:  written,
		logPath:  logPath,
	}, nil
}

// Record writes a single audit record.  Fire-and-forget: errors are printed to
// stderr but do not block the caller.
func (s *auditSink) Record(sessionID, toolName, decision, denialCode, condType string, details map[string]interface{}, obligs []string) {
	activityID := 1
	if decision == "deny" {
		activityID = 2
	}

	rec := auditRecord{
		ClassUID:      6003,
		CategoryUID:   6,
		ActivityID:    activityID,
		Time:          time.Now().UTC().Format(time.RFC3339Nano),
		RequestID:     uuid.New().String(),
		SessionID:     sessionID,
		ToolName:      toolName,
		Decision:      decision,
		DenialCode:    denialCode,
		ConditionType: condType,
		Details:       details,
		Obligations:   obligs,
	}

	// Sign the record (without the HMAC field).
	body, err := json.Marshal(rec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox-mcp] audit marshal error: %v\n", err)
		return
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(body)
	rec.HMAC = "sha256:" + hex.EncodeToString(mac.Sum(nil))

	// Re-marshal with HMAC field.
	line, err := json.Marshal(rec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox-mcp] audit marshal error: %v\n", err)
		return
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.written+int64(len(line)) > s.maxBytes {
		s.rotate()
	}

	n, err := s.f.Write(line)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox-mcp] audit write error: %v\n", err)
		return
	}
	s.written += int64(n)
}

// Close flushes and closes the audit log file.
func (s *auditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		if err := s.f.Sync(); err != nil {
			return err
		}
		return s.f.Close()
	}
	return nil
}

// VerifyRecord re-computes the HMAC of a raw audit record line and reports
// whether the signature matches.
func (s *auditSink) VerifyRecord(line []byte) (bool, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(line, &m); err != nil {
		return false, err
	}
	storedHMAC, _ := m["_hmac"].(string)
	delete(m, "_hmac")

	body, err := json.Marshal(m)
	if err != nil {
		return false, err
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(body)
	want := "sha256:" + hex.EncodeToString(mac.Sum(nil))
	return storedHMAC == want, nil
}

func (s *auditSink) rotate() {
	if s.f == nil {
		return
	}
	_ = s.f.Close()
	rotated := s.logPath + "." + time.Now().UTC().Format("20060102T150405Z")
	_ = os.Rename(s.logPath, rotated)
	f, err := os.OpenFile(s.logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[eunox-mcp] audit rotate error: %v\n", err)
		s.f = nil
		return
	}
	s.f = f
	s.written = 0
}

// -----------------------------------------------------------------
// HMAC key management
// -----------------------------------------------------------------

func loadOrCreateAuditKey(keyPath string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(keyPath) //nolint:gosec // G304: path is the hardcoded default key path expanded from ~/.eunox/audit.key
	if err == nil {
		key := make([]byte, hex.DecodedLen(len(data)))
		n, err := hex.Decode(key, data)
		if err == nil && n == 32 {
			return key[:n], nil
		}
	}

	// Generate a new 32-byte random key.
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generating audit key: %w", err)
	}

	encoded := make([]byte, hex.EncodedLen(len(key)))
	hex.Encode(encoded, key)
	if err := os.WriteFile(keyPath, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("writing audit key: %w", err)
	}
	return key, nil
}

// expandHome replaces a leading "~/" with the user's home directory.
func expandHome(p string) string {
	if !filepath.IsAbs(p) && len(p) >= 2 && p[:2] == "~/" {
		home, err := os.UserHomeDir()
		if err == nil {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}
