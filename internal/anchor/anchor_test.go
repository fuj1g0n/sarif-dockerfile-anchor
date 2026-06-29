package anchor

import (
	"testing"

	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/cyclonedx"
	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/dockerfile"
)

const dockerfileSrc = `FROM eclipse-temurin:21-jdk AS build
RUN ./gradlew bootJar
FROM eclipse-temurin:21-jre-jammy AS runtime
RUN dpkg -i curl_7.81.0-1_amd64.deb`

func newResult(rule, pkg, sev string) map[string]any {
	return map[string]any{
		"ruleId": rule,
		"message": map[string]any{
			"text": "Package: " + pkg + ", Severity: " + sev + ", Fix: none",
		},
		"locations": []any{
			map[string]any{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": "registry/quiz-app"},
					"region":           map[string]any{"startLine": float64(1)},
				},
			},
		},
	}
}

func newDoc(results ...map[string]any) map[string]any {
	items := make([]any, len(results))
	for i, r := range results {
		items[i] = r
	}
	return map[string]any{
		"version": "2.1.0",
		"runs": []any{
			map[string]any{"results": items},
		},
	}
}

func resultsOf(doc map[string]any) []any {
	return doc["runs"].([]any)[0].(map[string]any)["results"].([]any)
}

func region(r map[string]any) map[string]any {
	return r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["region"].(map[string]any)
}

func uri(r map[string]any) string {
	return r["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)["artifactLocation"].(map[string]any)["uri"].(string)
}

func testIndex() *cyclonedx.Index {
	return cyclonedx.NewIndex(map[string]map[string]struct{}{
		"curl":        {"deb": {}},
		"libssl3":     {"deb": {}},
		"zlib1g":      {"deb": {}},
		"spring-core": {"maven": {}},
	})
}

func testConfig(df *dockerfile.Dockerfile) Config {
	return Config{
		DockerfileURI:  "Dockerfile",
		BaseFromLine:   df.FinalStageFromLine(),
		BaseSeverities: ParseSeverities("high,critical"),
		LinkTransitive: true,
	}
}

func TestEnrichBuckets(t *testing.T) {
	df := dockerfile.Parse(dockerfileSrc)
	doc := newDoc(
		newResult("CVE-INJ", "curl", "Low"),             // injected (any severity)
		newResult("CVE-BASE", "libssl3", "High"),        // base, kept
		newResult("CVE-BASELOW", "zlib1g", "Low"),       // base, filtered out -> left
		newResult("CVE-APP", "spring-core", "Critical"), // application -> left
		newResult("CVE-NOPKG", "", "High"),              // unparseable package -> left
	)

	res := Enrich(doc, testIndex(), df, testConfig(df))

	if res.Injected != 1 || res.Base != 1 || res.Left != 3 {
		t.Fatalf("buckets = injected:%d base:%d left:%d, want 1/1/3", res.Injected, res.Base, res.Left)
	}

	r := resultsOf(doc)

	// Injected curl -> install line (4) on Dockerfile.
	if got := region(r[0].(map[string]any))["startLine"]; got != 4 {
		t.Errorf("injected startLine = %v, want 4", got)
	}
	if got := uri(r[0].(map[string]any)); got != "Dockerfile" {
		t.Errorf("injected uri = %q, want Dockerfile", got)
	}

	// Base libssl3 -> runtime FROM line (3).
	if got := region(r[1].(map[string]any))["startLine"]; got != 3 {
		t.Errorf("base startLine = %v, want 3", got)
	}

	// Stable fingerprint present on an anchored finding.
	fp := r[0].(map[string]any)["partialFingerprints"].(map[string]any)["primaryLocationLineHash"]
	if fp == nil || fp == "" {
		t.Error("expected partialFingerprints on anchored result")
	}
}

func TestEnrichPreservesUnknownFields(t *testing.T) {
	df := dockerfile.Parse(dockerfileSrc)
	doc := newDoc(newResult("CVE-APP", "spring-core", "High"))
	// Application finding is left untouched, including its original location.
	Enrich(doc, testIndex(), df, testConfig(df))
	if got := uri(resultsOf(doc)[0].(map[string]any)); got != "registry/quiz-app" {
		t.Errorf("left finding uri = %q, want untouched registry/quiz-app", got)
	}
	if doc["version"] != "2.1.0" {
		t.Error("top-level version field must be preserved")
	}
}

func TestEnrichEmptyBaseSeveritiesKeepsAll(t *testing.T) {
	df := dockerfile.Parse(dockerfileSrc)
	cfg := testConfig(df)
	cfg.BaseSeverities = ParseSeverities("") // empty => keep all base findings
	doc := newDoc(newResult("CVE-BASELOW", "zlib1g", "Low"))
	res := Enrich(doc, testIndex(), df, cfg)
	if res.Base != 1 {
		t.Errorf("empty base-severity should keep base finding, got base=%d", res.Base)
	}
}

func TestEndColumnMinimumTwo(t *testing.T) {
	df := dockerfile.Parse("\nFROM x") // line 1 is empty
	if got := endColumn(df, 1); got != 2 {
		t.Errorf("endColumn(empty line) = %d, want 2", got)
	}
}

func TestParseSeverities(t *testing.T) {
	s := ParseSeverities(" high , Critical ,, ")
	if !s["HIGH"] || !s["CRITICAL"] || len(s) != 2 {
		t.Errorf("ParseSeverities = %v, want {HIGH,CRITICAL}", s)
	}
}

func TestEnrichTreatsAllOSTypesAsOS(t *testing.T) {
	df := dockerfile.Parse(dockerfileSrc)
	eco := cyclonedx.NewIndex(map[string]map[string]struct{}{
		"openssl-libs": {"rpm": {}},  // RPM base package
		"musl":         {"apk": {}},  // Alpine base package
		"glibc":        {"alpm": {}}, // Arch base package
		"spring-core":  {"maven": {}},
	})
	doc := newDoc(
		newResult("CVE-RPM", "openssl-libs", "High"),
		newResult("CVE-APK", "musl", "Critical"),
		newResult("CVE-ALPM", "glibc", "High"),
		newResult("CVE-APP", "spring-core", "Critical"),
	)
	res := Enrich(doc, eco, df, testConfig(df))
	// rpm/apk/alpm are OS packages not present in the Dockerfile -> base FROM.
	if res.Base != 3 {
		t.Errorf("rpm/apk/alpm should anchor to base FROM, got base=%d", res.Base)
	}
	// maven stays at the image reference.
	if res.Left != 1 {
		t.Errorf("maven should be left at image, got left=%d", res.Left)
	}
}

// transitiveDockerfile installs only curl on its single RUN line (line 2). The
// SBOM below makes libssl3t64 a transitive dependency of curl that is not named
// anywhere in the Dockerfile.
const transitiveDockerfile = "FROM ubuntu:24.04\nRUN apt-get install -y --allow-downgrades curl=8.5.0-2ubuntu10"

const transitiveSBOM = `{
  "components": [
    {"name":"curl",        "bom-ref":"r-curl", "purl":"pkg:deb/ubuntu/curl@8.5.0-2ubuntu10?arch=amd64"},
    {"name":"libcurl4t64", "bom-ref":"r-lcurl","purl":"pkg:deb/ubuntu/libcurl4t64@8.5.0-2ubuntu10?arch=amd64"},
    {"name":"libssl3t64",  "bom-ref":"r-ssl",  "purl":"pkg:deb/ubuntu/libssl3t64@3.0.13-0ubuntu3.9?arch=amd64"}
  ],
  "dependencies": [
    {"ref":"r-curl",  "dependsOn":["r-lcurl"]},
    {"ref":"r-lcurl", "dependsOn":["r-ssl"]}
  ]
}`

func TestEnrichTransitiveAnchorsToInstaller(t *testing.T) {
	df := dockerfile.Parse(transitiveDockerfile)
	eco, err := cyclonedx.Parse([]byte(transitiveSBOM))
	if err != nil {
		t.Fatalf("parse sbom: %v", err)
	}
	// libssl3t64 is "Low": below the base-severity filter, so it would be
	// dropped if it fell through to the base bucket. The transitive tier must
	// anchor it to the curl install line regardless of severity.
	doc := newDoc(newResult("CVE-SSL", "libssl3t64", "Low"))
	res := Enrich(doc, eco, df, testConfig(df))

	if res.Transitive != 1 || res.Injected != 0 || res.Base != 0 || res.Left != 0 {
		t.Fatalf("buckets = injected:%d transitive:%d base:%d left:%d, want 0/1/0/0",
			res.Injected, res.Transitive, res.Base, res.Left)
	}
	r := resultsOf(doc)[0].(map[string]any)
	if got := region(r)["startLine"]; got != 2 {
		t.Errorf("transitive startLine = %v, want 2 (curl install line)", got)
	}
	if got := uri(r); got != "Dockerfile" {
		t.Errorf("transitive uri = %q, want Dockerfile", got)
	}
}

func TestEnrichTransitiveDisabledFallsBackToBase(t *testing.T) {
	df := dockerfile.Parse(transitiveDockerfile)
	eco, err := cyclonedx.Parse([]byte(transitiveSBOM))
	if err != nil {
		t.Fatalf("parse sbom: %v", err)
	}
	cfg := testConfig(df)
	cfg.LinkTransitive = false
	cfg.BaseSeverities = ParseSeverities("") // keep all base findings
	doc := newDoc(newResult("CVE-SSL", "libssl3t64", "High"))
	res := Enrich(doc, eco, df, cfg)

	if res.Base != 1 || res.Transitive != 0 {
		t.Fatalf("with link-transitive off, want base=1 transitive=0, got base=%d transitive=%d",
			res.Base, res.Transitive)
	}
	if got := region(resultsOf(doc)[0].(map[string]any))["startLine"]; got != 1 {
		t.Errorf("base startLine = %v, want 1 (FROM line)", got)
	}
}
