package cyclonedx

import "testing"

func TestParseClassifiesByPurlType(t *testing.T) {
	data := []byte(`{
	  "components": [
	    {"name": "curl",        "purl": "pkg:deb/ubuntu/curl@7.81.0-1?arch=amd64"},
	    {"name": "libssl3",     "purl": "pkg:deb/ubuntu/libssl3@3.0.2"},
	    {"name": "spring-core", "purl": "pkg:maven/org.springframework/spring-core@6.1.0"},
	    {"name": "no-purl"},
	    {"purl": "pkg:deb/ubuntu/anon@1"}
	  ]
	}`)

	idx, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if !idx.Has("curl", "deb") {
		t.Error("curl should be classified as deb")
	}
	if !idx.Has("libssl3", "deb") {
		t.Error("libssl3 should be classified as deb")
	}
	if idx.Has("spring-core", "deb") {
		t.Error("spring-core (maven) must not be classified as deb")
	}
	if !idx.Has("spring-core", "maven") {
		t.Error("spring-core should be classified as maven")
	}
	if idx.Has("no-purl", "deb") {
		t.Error("component without purl must not be indexed")
	}
}

func TestParseInvalidJSON(t *testing.T) {
	if _, err := Parse([]byte("not json")); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParseNestedComponents(t *testing.T) {
	data := []byte(`{"components":[
	  {"name":"outer","purl":"pkg:maven/g/outer@1","components":[
	    {"name":"libssl3","purl":"pkg:deb/ubuntu/libssl3@3.0.2"}
	  ]}
	]}`)
	idx, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if !idx.IsOS("libssl3") {
		t.Error("nested deb component should be indexed as an OS package")
	}
	if !idx.Has("outer", "maven") {
		t.Error("top-level maven component should still be indexed")
	}
}

func TestNilIndexHasIsFalse(t *testing.T) {
	if NewIndex(nil).Has("x", "deb") {
		t.Error("empty index must report false")
	}
}

func TestIsOSAcrossPurlTypes(t *testing.T) {
	idx := NewIndex(map[string]map[string]struct{}{
		"curl":         {"deb": {}},
		"openssl-libs": {"rpm": {}},
		"musl":         {"apk": {}},
		"glibc":        {"alpm": {}},
		"qnx-base":     {"qpkg": {}},
		"yocto-core":   {"yocto": {}},
		"spring-core":  {"maven": {}},
		"left-pad":     {"npm": {}},
		"numpy":        {"conda": {}},
		"boost":        {"conan": {}},
		"blob":         {"generic": {}},
	})
	for _, name := range []string{"curl", "openssl-libs", "musl", "glibc", "qnx-base", "yocto-core"} {
		if !idx.IsOS(name) {
			t.Errorf("%s should be classified as an OS package", name)
		}
	}
	for _, name := range []string{"spring-core", "left-pad", "numpy", "boost", "blob", "unknown"} {
		if idx.IsOS(name) {
			t.Errorf("%s must not be classified as an OS package", name)
		}
	}
}

// depGraphSBOM models curl -> libcurl4t64 -> libssl3t64, with zlib1g hanging
// off curl as a sibling, so the reverse-graph walk has more than one path.
const depGraphSBOM = `{
  "components": [
    {"name":"curl",        "bom-ref":"r-curl", "purl":"pkg:deb/ubuntu/curl@8.5.0?arch=amd64"},
    {"name":"libcurl4t64", "bom-ref":"r-lcurl","purl":"pkg:deb/ubuntu/libcurl4t64@8.5.0?arch=amd64"},
    {"name":"libssl3t64",  "bom-ref":"r-ssl",  "purl":"pkg:deb/ubuntu/libssl3t64@3.0.13?arch=amd64"},
    {"name":"zlib1g",      "bom-ref":"r-zlib", "purl":"pkg:deb/ubuntu/zlib1g@1.3?arch=amd64"}
  ],
  "dependencies": [
    {"ref":"r-curl",  "dependsOn":["r-lcurl","r-zlib"]},
    {"ref":"r-lcurl", "dependsOn":["r-ssl"]}
  ]
}`

func TestNearestInstalledAncestor(t *testing.T) {
	idx, err := Parse([]byte(depGraphSBOM))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	installed := func(names ...string) func(string) bool {
		set := map[string]bool{}
		for _, n := range names {
			set[n] = true
		}
		return func(n string) bool { return set[n] }
	}

	// libssl3t64's only installed ancestor is curl (two hops up).
	if anc, ok := idx.NearestInstalledAncestor("libssl3t64", installed("curl")); !ok || anc != "curl" {
		t.Errorf("nearest ancestor of libssl3t64 = %q,%v, want curl,true", anc, ok)
	}
	// The nearer ancestor wins when both are installed.
	if anc, ok := idx.NearestInstalledAncestor("libssl3t64", installed("curl", "libcurl4t64")); !ok || anc != "libcurl4t64" {
		t.Errorf("nearest ancestor with both installed = %q,%v, want libcurl4t64,true", anc, ok)
	}
	// A root package has no ancestor.
	if anc, ok := idx.NearestInstalledAncestor("curl", installed("curl")); ok {
		t.Errorf("curl should have no installed ancestor, got %q", anc)
	}
	// No installed ancestor anywhere.
	if _, ok := idx.NearestInstalledAncestor("libssl3t64", installed("zlib1g")); ok {
		t.Error("zlib1g is not an ancestor of libssl3t64; expected no match")
	}
}

func TestNearestInstalledAncestorEmptyGraph(t *testing.T) {
	idx := NewIndex(map[string]map[string]struct{}{"libssl3t64": {"deb": {}}})
	if _, ok := idx.NearestInstalledAncestor("libssl3t64", func(string) bool { return true }); ok {
		t.Error("index without a dependency graph must report no ancestor")
	}
}
