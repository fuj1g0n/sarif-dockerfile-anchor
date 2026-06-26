// Package anchor rewrites Microsoft Defender (MDVM) container-scan SARIF result
// locations so that OS-package findings point at the Dockerfile line that
// introduced the package, instead of the opaque image reference. This lets
// GitHub code scanning render the findings as pull-request inline annotations
// and diff-gate checks, matching how CodeQL behaves on source files.
//
// The SARIF document is handled as a generic map so that every field the tool
// does not understand is preserved byte-for-byte on output; only
// results[].locations[0] and results[].partialFingerprints are touched.
package anchor

import (
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"strings"

	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/cyclonedx"
	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/dockerfile"
)

var (
	rePackage  = regexp.MustCompile(`Package:\s*([^,\n]+?)\s*,`)
	reSeverity = regexp.MustCompile(`Severity:\s*([A-Za-z]+)`)
)

// Config controls how findings are anchored.
type Config struct {
	// DockerfileURI is the repo-relative path written into the SARIF
	// artifactLocation (e.g. "Dockerfile").
	DockerfileURI string
	// BaseFromLine is the 1-based Dockerfile line of the base-image FROM.
	BaseFromLine int
	// BaseSeverities is the set (uppercased) of severities for which base-image
	// OS findings are kept as inline annotations. Empty means "keep all".
	BaseSeverities map[string]bool
}

// Result reports how many findings landed in each bucket.
type Result struct {
	Injected int // anchored to a Dockerfile install/download line
	Base     int // anchored to the base-image FROM line
	Left     int // left at the image reference (application/filtered/unparseable)
}

// ParseSeverities turns a comma-separated list like "high,critical" into an
// uppercased set.
func ParseSeverities(csv string) map[string]bool {
	out := map[string]bool{}
	for _, p := range strings.Split(csv, ",") {
		p = strings.ToUpper(strings.TrimSpace(p))
		if p != "" {
			out[p] = true
		}
	}
	return out
}

// Enrich mutates the generic SARIF document in place and returns per-bucket
// counters.
func Enrich(doc map[string]any, eco *cyclonedx.Index, df *dockerfile.Dockerfile, cfg Config) Result {
	var res Result
	runs, _ := doc["runs"].([]any)
	for _, r := range runs {
		run, ok := r.(map[string]any)
		if !ok {
			continue
		}
		results, _ := run["results"].([]any)
		for _, item := range results {
			res.add(anchorOne(item, eco, df, cfg))
		}
	}
	return res
}

func (r *Result) add(bucket string) {
	switch bucket {
	case "injected":
		r.Injected++
	case "base":
		r.Base++
	default:
		r.Left++
	}
}

func anchorOne(item any, eco *cyclonedx.Index, df *dockerfile.Dockerfile, cfg Config) string {
	res, ok := item.(map[string]any)
	if !ok {
		return "left"
	}

	text := messageText(res)
	m := rePackage.FindStringSubmatch(text)
	if m == nil {
		return "left"
	}
	name := strings.TrimSpace(m[1])

	severity := ""
	if sm := reSeverity.FindStringSubmatch(text); sm != nil {
		severity = strings.ToUpper(sm[1])
	}

	// Application/language packages (non-deb) stay at the image location; they
	// are Dependabot/CodeQL territory.
	if !eco.Has(name, "deb") {
		return "left"
	}

	var lineNo int
	var bucket string
	if ln, found := df.InstallLine(name); found {
		lineNo, bucket = ln, "injected"
	} else {
		// Base-image OS package: anchor to the final-stage FROM line, but keep
		// only the configured severities as inline annotations to limit noise.
		if len(cfg.BaseSeverities) > 0 && !cfg.BaseSeverities[severity] {
			return "left"
		}
		lineNo, bucket = cfg.BaseFromLine, "base"
	}

	locs, _ := res["locations"].([]any)
	if len(locs) == 0 {
		return "left"
	}
	loc0, ok := locs[0].(map[string]any)
	if !ok {
		return "left"
	}
	phys, ok := loc0["physicalLocation"].(map[string]any)
	if !ok {
		phys = map[string]any{}
		loc0["physicalLocation"] = phys
	}
	phys["artifactLocation"] = map[string]any{"uri": cfg.DockerfileURI}
	phys["region"] = map[string]any{
		"startLine":   lineNo,
		"startColumn": 1,
		"endLine":     lineNo,
		"endColumn":   endColumn(df, lineNo),
	}

	ruleID, _ := res["ruleId"].(string)
	res["partialFingerprints"] = map[string]any{
		"primaryLocationLineHash": fingerprint(ruleID, name) + ":1",
	}
	return bucket
}

func endColumn(df *dockerfile.Dockerfile, line int) int {
	n := df.LineLength(line) + 1
	if n < 2 {
		return 2
	}
	return n
}

func messageText(res map[string]any) string {
	msg, ok := res["message"].(map[string]any)
	if !ok {
		return ""
	}
	t, _ := msg["text"].(string)
	return t
}

// fingerprint produces a stable, line-independent identity so re-runs do not
// churn alerts.
func fingerprint(ruleID, name string) string {
	sum := sha1.Sum([]byte(ruleID + ":" + name))
	return hex.EncodeToString(sum[:])[:16]
}
