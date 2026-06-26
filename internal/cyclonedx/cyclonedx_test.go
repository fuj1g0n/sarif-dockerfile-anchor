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
