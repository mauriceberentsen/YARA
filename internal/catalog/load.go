package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const maxSnapshotBytes = 4 << 20

func Load(path string) (Snapshot, error) {
	var snapshot Snapshot
	file, err := os.Open(path)
	if err != nil {
		return snapshot, fmt.Errorf("open catalog snapshot: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSnapshotBytes+1))
	if err != nil {
		return snapshot, fmt.Errorf("read catalog snapshot: %w", err)
	}
	if len(data) > maxSnapshotBytes {
		return snapshot, errors.New("catalog snapshot exceeds the 4 MiB input limit")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&snapshot); err != nil {
		return snapshot, fmt.Errorf("decode catalog snapshot: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return snapshot, errors.New("multiple catalog documents are not allowed")
		}
		return snapshot, fmt.Errorf("decode trailing catalog data: %w", err)
	}
	if report := snapshot.Validate(); !report.Valid {
		return snapshot, fmt.Errorf("catalog snapshot is invalid: %s", report.Diagnostics[0].Code)
	}
	return snapshot, nil
}
