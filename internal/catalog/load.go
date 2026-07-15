package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxManifestBytes = 4 << 20

type manifestHeader struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   any    `yaml:"metadata"`
	Spec       any    `yaml:"spec"`
}

func Load(path string) (Snapshot, error) {
	snapshot, err := decodeStrict[Snapshot](path)
	if err != nil {
		return Snapshot{}, fmt.Errorf("load catalog snapshot: %w", err)
	}
	if items := validateIndex(snapshot); len(items) > 0 {
		return Snapshot{}, fmt.Errorf("catalog snapshot is invalid: %s", items[0].Code)
	}
	sort.Strings(snapshot.Spec.Manifests)
	set, err := loadManifestSet(filepath.Dir(path), snapshot.Spec.Manifests)
	if err != nil {
		return Snapshot{}, err
	}
	snapshot.manifests = set
	snapshot.candidates = compileCandidates(set)
	if report := snapshot.Validate(); !report.Valid {
		return Snapshot{}, fmt.Errorf("catalog snapshot is invalid: %s", report.Diagnostics[0].Code)
	}
	return snapshot, nil
}

func loadManifestSet(root string, references []string) (manifestSet, error) {
	var set manifestSet
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return set, fmt.Errorf("resolve catalog root: %w", err)
	}
	for _, reference := range references {
		path, err := safeManifestPath(rootAbsolute, reference)
		if err != nil {
			return set, err
		}
		header, err := decodeStrict[manifestHeader](path)
		if err != nil {
			return set, fmt.Errorf("load manifest %s: %w", reference, err)
		}
		if header.APIVersion != APIVersion {
			return set, fmt.Errorf("manifest %s has unsupported apiVersion", reference)
		}
		switch header.Kind {
		case "Capability":
			item, err := decodeStrict[CapabilityManifest](path)
			if err != nil {
				return set, fmt.Errorf("load capability %s: %w", reference, err)
			}
			set.Capabilities = append(set.Capabilities, item)
		case "Component":
			item, err := decodeStrict[ComponentManifest](path)
			if err != nil {
				return set, fmt.Errorf("load component %s: %w", reference, err)
			}
			set.Components = append(set.Components, item)
		case "Model":
			item, err := decodeStrict[ModelManifest](path)
			if err != nil {
				return set, fmt.Errorf("load model %s: %w", reference, err)
			}
			set.Models = append(set.Models, item)
		case "HardwareProfile":
			item, err := decodeStrict[HardwareProfileManifest](path)
			if err != nil {
				return set, fmt.Errorf("load hardware profile %s: %w", reference, err)
			}
			set.Hardware = append(set.Hardware, item)
		case "CompatibilityAssertion":
			item, err := decodeStrict[CompatibilityAssertion](path)
			if err != nil {
				return set, fmt.Errorf("load compatibility assertion %s: %w", reference, err)
			}
			set.Compatibility = append(set.Compatibility, item)
		default:
			return set, fmt.Errorf("manifest %s has unsupported kind %q", reference, header.Kind)
		}
	}
	sortManifestSet(&set)
	return set, nil
}

func safeManifestPath(root, reference string) (string, error) {
	if filepath.IsAbs(reference) {
		return "", fmt.Errorf("manifest reference %q must be relative", reference)
	}
	path := filepath.Clean(filepath.Join(root, reference))
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return "", fmt.Errorf("resolve manifest reference %q: %w", reference, err)
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("manifest reference %q escapes the catalog root", reference)
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve catalog root symlinks: %w", err)
	}
	resolvedPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve manifest reference %q: %w", reference, err)
	}
	resolvedRelative, err := filepath.Rel(resolvedRoot, resolvedPath)
	if err != nil {
		return "", fmt.Errorf("resolve manifest reference %q: %w", reference, err)
	}
	if resolvedRelative == ".." || strings.HasPrefix(resolvedRelative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("manifest reference %q escapes the catalog root through a symbolic link", reference)
	}
	return path, nil
}

func sortManifestSet(set *manifestSet) {
	sort.SliceStable(set.Capabilities, func(i, j int) bool { return set.Capabilities[i].Metadata.ID < set.Capabilities[j].Metadata.ID })
	sort.SliceStable(set.Components, func(i, j int) bool { return set.Components[i].Metadata.ID < set.Components[j].Metadata.ID })
	sort.SliceStable(set.Models, func(i, j int) bool { return set.Models[i].Metadata.ID < set.Models[j].Metadata.ID })
	sort.SliceStable(set.Hardware, func(i, j int) bool { return set.Hardware[i].Metadata.ID < set.Hardware[j].Metadata.ID })
	sort.SliceStable(set.Compatibility, func(i, j int) bool { return set.Compatibility[i].Metadata.ID < set.Compatibility[j].Metadata.ID })
}

func decodeStrict[T any](path string) (T, error) {
	var value T
	file, err := os.Open(path)
	if err != nil {
		return value, fmt.Errorf("open: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil {
		return value, fmt.Errorf("read: %w", err)
	}
	if len(data) > maxManifestBytes {
		return value, errors.New("manifest exceeds the 4 MiB input limit")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&value); err != nil {
		return value, fmt.Errorf("decode: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return value, errors.New("multiple YAML documents are not allowed")
		}
		return value, fmt.Errorf("decode trailing data: %w", err)
	}
	return value, nil
}
