package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"mdvm"}},"results":[
		{"ruleId":"CVE-1","message":{"text":"Severity: High Package: curl, CVE-1"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"reg/app"},"region":{"startLine":1}}}]},
		{"ruleId":"CVE-2","message":{"text":"Severity: Critical Package: spring-core, CVE-2"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"reg/app"},"region":{"startLine":1}}}]}
	]}]}`
	testSBOM = `{"components":[
		{"name":"curl","purl":"pkg:deb/ubuntu/curl@7.81.0-1"},
		{"name":"spring-core","purl":"pkg:maven/org.springframework/spring-core@6"}
	]}`
	testDockerfile = "FROM eclipse-temurin:21-jdk AS build\nFROM eclipse-temurin:21-jre AS runtime\nRUN dpkg -i curl_7.81.0-1_amd64.deb\n"
)

func writeInputs(t *testing.T) (sarif, sbom, df, dir string) {
	t.Helper()
	dir = t.TempDir()
	sarif = filepath.Join(dir, "image.sarif")
	sbom = filepath.Join(dir, "sbom.json")
	df = filepath.Join(dir, "Dockerfile")
	for path, content := range map[string]string{sarif: testSARIF, sbom: testSBOM, df: testDockerfile} {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}
	return sarif, sbom, df, dir
}

func TestRunWritesEnrichedFile(t *testing.T) {
	sarif, sbom, df, dir := writeInputs(t)
	out := filepath.Join(dir, "out.sarif")
	if code := run([]string{"--sarif", sarif, "--sbom", sbom, "--dockerfile", df, "--dockerfile-uri", "Dockerfile", "--output", out}); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	s := string(b)
	// curl is a deb OS package installed in the Dockerfile -> anchored there.
	if !strings.Contains(s, `"uri":"Dockerfile"`) {
		t.Errorf("expected the curl finding anchored to the Dockerfile, got:\n%s", s)
	}
	// spring-core is maven -> left at the image reference.
	if !strings.Contains(s, "reg/app") {
		t.Error("expected the maven finding left at the image reference")
	}
}

func TestRunWritesToStdout(t *testing.T) {
	sarif, sbom, df, _ := writeInputs(t)

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := run([]string{"--sarif", sarif, "--sbom", sbom, "--dockerfile", df})
	_ = w.Close()
	os.Stdout = orig
	if code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
	buf := make([]byte, 8192)
	n, _ := r.Read(buf)
	if !strings.Contains(string(buf[:n]), `"runs"`) {
		t.Error("expected SARIF JSON on stdout")
	}
}

func TestRunMissingRequiredFlags(t *testing.T) {
	if code := run([]string{"--sarif", "only-sarif"}); code != 2 {
		t.Errorf("run with missing flags = %d, want 2", code)
	}
}

func TestRunUnknownFlag(t *testing.T) {
	if code := run([]string{"--nope"}); code != 2 {
		t.Errorf("run with unknown flag = %d, want 2", code)
	}
}

func TestRunVersion(t *testing.T) {
	if code := run([]string{"--version"}); code != 0 {
		t.Errorf("run --version = %d, want 0", code)
	}
}

func TestRunUnreadableSarif(t *testing.T) {
	_, sbom, df, _ := writeInputs(t)
	if code := run([]string{"--sarif", "/no/such/file.sarif", "--sbom", sbom, "--dockerfile", df}); code != 1 {
		t.Errorf("run with bad sarif = %d, want 1", code)
	}
}

func TestRunInvalidSarifJSON(t *testing.T) {
	_, sbom, df, dir := writeInputs(t)
	bad := filepath.Join(dir, "bad.sarif")
	if err := os.WriteFile(bad, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--sarif", bad, "--sbom", sbom, "--dockerfile", df}); code != 1 {
		t.Errorf("run with invalid sarif JSON = %d, want 1", code)
	}
}

func TestRunMissingSbomIsNonFatal(t *testing.T) {
	sarif, _, df, dir := writeInputs(t)
	out := filepath.Join(dir, "out.sarif")
	// A missing SBOM is a warning, not an error: no finding is OS-classified.
	if code := run([]string{"--sarif", sarif, "--sbom", "/no/such/sbom.json", "--dockerfile", df, "--output", out}); code != 0 {
		t.Errorf("run with missing sbom = %d, want 0", code)
	}
}
