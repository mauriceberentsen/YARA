package resources

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestPublicSchemasAreValidJSONDocuments(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "schemas", "yara.dev", "v1alpha1", "*.schema.json"))
	if err != nil {
		t.Fatalf("find schemas: %v", err)
	}
	if len(paths) != 18 {
		t.Fatalf("expected eighteen public schemas, found %d", len(paths))
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, key := range []string{"$schema", "$id"} {
			value, ok := schema[key].(string)
			if !ok || value == "" {
				t.Fatalf("schema %s must declare a non-empty %s", path, key)
			}
		}
	}
}
