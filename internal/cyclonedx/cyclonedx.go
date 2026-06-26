// Package cyclonedx provides a minimal reader for CycloneDX SBOM JSON that
// indexes component names by the ecosystem type encoded in their package URL
// (purl). It is intentionally tolerant: only the fields needed to classify a
// finding as an OS package (pkg:deb/apk/rpm) versus an application/language
// package are parsed.
package cyclonedx

import (
	"encoding/json"
	"regexp"
	"strings"
)

// rePurl extracts the type segment of a purl, e.g. "deb" from
// "pkg:deb/ubuntu/curl@7.81.0-1?arch=amd64".
var rePurl = regexp.MustCompile(`^pkg:([^/]+)/`)

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

type sbomDoc struct {
	Components []struct {
		Name string `json:"name"`
		Purl string `json:"purl"`
	} `json:"components"`
}

// Parse reads a CycloneDX SBOM (JSON) and returns the name->ecosystem index.
func Parse(data []byte) (*Index, error) {
	var d sbomDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, err
	}
	m := map[string]map[string]struct{}{}
	for _, c := range d.Components {
		match := rePurl.FindStringSubmatch(c.Purl)
		if match == nil || c.Name == "" {
			continue
		}
		ecosystem := strings.ToLower(match[1])
		set, ok := m[c.Name]
		if !ok {
			set = map[string]struct{}{}
			m[c.Name] = set
		}
		set[ecosystem] = struct{}{}
	}
	return NewIndex(m), nil
}
