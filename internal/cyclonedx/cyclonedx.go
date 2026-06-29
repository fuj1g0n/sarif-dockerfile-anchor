// Package cyclonedx provides a minimal reader for CycloneDX SBOM JSON that
// indexes component names by the ecosystem type encoded in their package URL
// (purl). It is intentionally tolerant: only the fields needed to classify a
// finding as an operating-system (Linux distribution) package versus an
// application/language package are parsed. See OSPackageTypes for the purl
// types treated as OS packages.
package cyclonedx

import (
	"encoding/json"
	"sort"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
)

// Index maps a component name to the set of purl ecosystem types it was seen
// under (for example "deb", "maven", "golang") and, when built from a full
// SBOM, the reverse dependency graph used to attribute a transitive package to
// the package that pulled it in.
type Index struct {
	eco map[string]map[string]struct{}
	// parents is the reverse dependency graph at the component-name level:
	// parents[child] holds the set of package names that directly depend on
	// child. It is empty unless the index was built from an SBOM that carries a
	// top-level "dependencies" graph.
	parents map[string]map[string]struct{}
}

// NewIndex wraps a pre-built name -> ecosystem-set map. A nil map yields an
// empty index whose Has always reports false.
func NewIndex(m map[string]map[string]struct{}) *Index {
	if m == nil {
		m = map[string]map[string]struct{}{}
	}
	return &Index{eco: m, parents: map[string]map[string]struct{}{}}
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
	BOMRef     string          `json:"bom-ref"`
	Purl       string          `json:"purl"`
	Components []sbomComponent `json:"components"`
}

type sbomDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type sbomDoc struct {
	Components   []sbomComponent  `json:"components"`
	Dependencies []sbomDependency `json:"dependencies"`
}

// Parse reads a CycloneDX SBOM (JSON) and returns the name->ecosystem index
// together with the reverse dependency graph derived from the top-level
// "dependencies" section. Package URLs are parsed with the canonical purl
// parser, and nested components are walked recursively. Decoding only the
// name/purl/bom-ref shape keeps the reader agnostic to the CycloneDX spec
// version.
func Parse(data []byte) (*Index, error) {
	var d sbomDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	m := map[string]map[string]struct{}{}
	// refName maps a component bom-ref to its name so the bom-ref-keyed
	// dependency graph can be projected onto names.
	refName := map[string]string{}
	var walk func(comps []sbomComponent)
	walk = func(comps []sbomComponent) {
		for _, c := range comps {
			if c.Name != "" && c.BOMRef != "" {
				refName[c.BOMRef] = c.Name
			}
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

	idx := NewIndex(m)
	for _, dep := range d.Dependencies {
		parent := refName[dep.Ref]
		if parent == "" {
			continue
		}
		for _, childRef := range dep.DependsOn {
			child := refName[childRef]
			if child == "" || child == parent {
				continue
			}
			set, ok := idx.parents[child]
			if !ok {
				set = map[string]struct{}{}
				idx.parents[child] = set
			}
			set[parent] = struct{}{}
		}
	}
	return idx, nil
}

// NearestInstalledAncestor walks the reverse dependency graph upward from name
// and returns the closest ancestor package (one that transitively depends on
// name) for which installed reports true. Ancestors are explored breadth-first
// so the nearest match wins; ties at the same depth are broken alphabetically
// for deterministic output. name itself is never returned. It reports false
// when the graph is empty or no installed ancestor exists.
func (i *Index) NearestInstalledAncestor(name string, installed func(string) bool) (string, bool) {
	if name == "" || len(i.parents) == 0 {
		return "", false
	}
	visited := map[string]bool{name: true}
	queue := sortedKeys(i.parents[name])
	for _, n := range queue {
		visited[n] = true
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if installed(cur) {
			return cur, true
		}
		for _, p := range sortedKeys(i.parents[cur]) {
			if !visited[p] {
				visited[p] = true
				queue = append(queue, p)
			}
		}
	}
	return "", false
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
