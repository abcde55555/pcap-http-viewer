// Package plugins defines the extension interface and registry. A plugin sees
// each parsed HTTP transaction and may return Findings (e.g. sensitive-info
// matches). v1 ships one built-in plugin: the sensitive-info rule engine. The
// interface is deliberately small so additional capabilities (report export,
// entropy scanning, custom decoders, future Lua/JS scripting) can be added
// without changing the parser or storage layers.
package plugins

import (
	"pcap-http-viewer/internal/model"
)

// Plugin inspects a single HTTP transaction and returns zero or more findings.
// Implementations must be safe for concurrent use.
type Plugin interface {
	// Name is a stable identifier (e.g. "sensitive").
	Name() string
	// OnTransaction is called once per parsed HTTP transaction. It may inspect
	// headers and read bodies via the provided BodyReader. Returned findings
	// are attached to the transaction.
	OnTransaction(tx *model.HTTPTx, bodies BodyReader) []model.Finding
}

// BodyReader returns decoded body bytes for a given side. Plugins should read
// through this rather than touching BodyRef.Data directly (which may be empty
// when spilled to disk).
type BodyReader interface {
	ReadBody(tx *model.HTTPTx, side string) ([]byte, error)
}

// Registry holds the active plugins.
type Registry struct {
	plugins []Plugin
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds a plugin.
func (r *Registry) Register(p Plugin) { r.plugins = append(r.plugins, p) }

// Names returns the names of all registered plugins.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.plugins))
	for _, p := range r.plugins {
		names = append(names, p.Name())
	}
	return names
}

// Run executes all plugins on one transaction and returns the aggregated findings.
func (r *Registry) Run(tx *model.HTTPTx, bodies BodyReader) []model.Finding {
	var out []model.Finding
	for _, p := range r.plugins {
		out = append(out, p.OnTransaction(tx, bodies)...)
	}
	return out
}

// Plugins returns all registered plugins (for config UI).
func (r *Registry) Plugins() []Plugin { return r.plugins }
