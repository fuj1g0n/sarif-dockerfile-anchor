// Package cyclonedx provides a minimal reader for CycloneDX SBOM JSON that
// indexes component names by the ecosystem type encoded in their package URL
// (purl). It is intentionally tolerant: only the fields needed to classify a
// finding as an operating-system (Linux distribution) package versus an
// application/language package are parsed. See OSPackageTypes for the purl
// types treated as OS packages.
package cyclonedx

import (
	"encoding/json"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// Index maps a component name to the set of purl ecosystem types it was seen
// under (for example "deb", "maven", "golang").
type Index struct {
	eco map[string]map[string]struct{}
}

// NewIndex wraps a pre-built name -> ecosystem-set map. A nil map yields an
// empty index whose Has always reports false.
func NewIndex(m map[string]map[string]struct{}) *Index {
	if m == nil {
		m = map[string]map[string]struct{}{}
	}
	return &Index{eco: m}
}

// Has reports whether name appeared under the given ecosystem (e.g. "deb").
func (i *Index) Has(name, ecosystem string) bool {
	set, ok := i.eco[name]
	if !ok {
		return false
	}
	_, ok = set[ecosystem]
	return ok
}

// OSPackageTypes is the set of purl "type" values that denote operating-system
// (Linux distribution / system) packages, per the Package URL type definitions
// (https://github.com/package-url/purl-spec/tree/main/types). Findings whose
// SBOM component carries one of these types are eligible for remapping to the
// Dockerfile; every other type (maven, npm, pypi, golang, nuget, conda, conan,
// generic, ...) is an application/language package left at the image reference.
var OSPackageTypes = map[string]struct{}{
	"deb":   {}, // Debian, Debian derivatives, Ubuntu
	"rpm":   {}, // RHEL, Fedora, SUSE, and other RPM distros
	"apk":   {}, // Alpine Linux
	"alpm":  {}, // Arch Linux (libalpm/pacman)
	"qpkg":  {}, // QNX
	"yocto": {}, // Yocto Project (embedded Linux)
}

// IsOS reports whether name was seen under any OS/distro purl type
// (see OSPackageTypes).
func (i *Index) IsOS(name string) bool {
	for t := range i.eco[name] {
		if _, ok := OSPackageTypes[t]; ok {
			return true
		}
	}
	return false
}

type sbomComponent struct {
	Name       string          `json:"name"`
	Purl       string          `json:"purl"`
	Components []sbomComponent `json:"components"`
}

type sbomDoc struct {
	Components []sbomComponent `json:"components"`
}

// Parse reads a CycloneDX SBOM (JSON) and returns the name->ecosystem index.
// Package URLs are parsed with the canonical purl parser, and nested
// components are walked recursively. Decoding only the name/purl shape keeps
// the reader agnostic to the CycloneDX spec version.
func Parse(data []byte) (*Index, error) {
	var d sbomDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	m := map[string]map[string]struct{}{}
	var walk func(comps []sbomComponent)
	walk = func(comps []sbomComponent) {
		for _, c := range comps {
			if c.Name != "" && c.Purl != "" {
				if pu, err := packageurl.FromString(c.Purl); err == nil && pu.Type != "" {
					set, ok := m[c.Name]
					if !ok {
						set = map[string]struct{}{}
						m[c.Name] = set
					}
					set[strings.ToLower(pu.Type)] = struct{}{}
				}
			}
			walk(c.Components)
		}
	}
	walk(d.Components)
	return NewIndex(m), nil
}
