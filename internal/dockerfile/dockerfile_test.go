package dockerfile

import "testing"

const sample = `FROM eclipse-temurin:21-jdk AS build
RUN ./gradlew bootJar
FROM eclipse-temurin:21-jre-jammy AS runtime
RUN dpkg -i curl_7.81.0-1_amd64.deb libcurl4_7.81.0-1_amd64.deb
RUN apt-get install -y git=1:2.34.1-1ubuntu1`

func TestFinalStageFromLine(t *testing.T) {
	df := Parse(sample)
	if got := df.FinalStageFromLine(); got != 3 {
		t.Errorf("FinalStageFromLine = %d, want 3", got)
	}
}

func TestFinalStageFromLineLastOfMany(t *testing.T) {
	df := Parse("FROM a:1\nFROM b:2\nRUN echo hi")
	if got := df.FinalStageFromLine(); got != 2 {
		t.Errorf("FinalStageFromLine last-of-many = %d, want 2", got)
	}
}

func TestFinalStageFromLineNoFrom(t *testing.T) {
	df := Parse("RUN echo hi\nRUN echo bye")
	if got := df.FinalStageFromLine(); got != 1 {
		t.Errorf("FinalStageFromLine no-FROM = %d, want 1", got)
	}
}

func TestInstallLineDebFilename(t *testing.T) {
	df := Parse(sample)
	if got, ok := df.InstallLine("curl"); !ok || got != 4 {
		t.Errorf("InstallLine(curl) = (%d,%v), want (4,true)", got, ok)
	}
}

func TestInstallLineAptPin(t *testing.T) {
	df := Parse(sample)
	if got, ok := df.InstallLine("git"); !ok || got != 5 {
		t.Errorf("InstallLine(git) = (%d,%v), want (5,true)", got, ok)
	}
}

func TestInstallLineNoBoundaryFalsePositive(t *testing.T) {
	// "url" must not match inside "curl_..." (boundary guard).
	df := Parse(sample)
	if got, ok := df.InstallLine("url"); ok {
		t.Errorf("InstallLine(url) matched line %d, want no match", got)
	}
}

func TestInstallLineMissing(t *testing.T) {
	df := Parse(sample)
	if _, ok := df.InstallLine("openssl"); ok {
		t.Error("InstallLine(openssl) should not match")
	}
}

func TestLineLength(t *testing.T) {
	df := Parse("FROM a\nRUN x")
	if got := df.LineLength(1); got != 6 {
		t.Errorf("LineLength(1) = %d, want 6", got)
	}
	if got := df.LineLength(99); got != 0 {
		t.Errorf("LineLength(out-of-range) = %d, want 0", got)
	}
}
