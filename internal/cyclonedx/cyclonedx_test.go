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
