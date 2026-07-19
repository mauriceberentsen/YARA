// Package renderer contains pure, offline translations from immutable plans to
// reviewable deployment bundles. Renderers never inspect or mutate a target.
package renderer

import (
	"fmt"

	"github.com/mauriceberentsen/YARA/internal/catalog"
	"github.com/mauriceberentsen/YARA/internal/resources"
)

type Identity struct {
	Name    string
	Version string
	Target  string
}

type Renderer interface {
	Identity() Identity
	Render(name string, plan resources.PlatformPlan, snapshot catalog.Snapshot) (resources.DeploymentBundle, error)
}

type UnsupportedError struct {
	Reason string
	Path   string
}

func (e UnsupportedError) Error() string {
	if e.Path == "" {
		return e.Reason
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Reason)
}
