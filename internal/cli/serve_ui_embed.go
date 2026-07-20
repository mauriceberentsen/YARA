package cli

import (
	"embed"
	"fmt"
	"io/fs"
)

//go:embed webui/dist/* webui/dist/assets/*
var embeddedWebUIAssets embed.FS

func serveUIFileSystem() (fs.FS, error) {
	assets, err := fs.Sub(embeddedWebUIAssets, "webui/dist")
	if err != nil {
		return nil, fmt.Errorf("load embedded web ui assets: %w", err)
	}
	return assets, nil
}
