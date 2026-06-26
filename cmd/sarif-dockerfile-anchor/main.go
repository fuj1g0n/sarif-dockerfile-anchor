// Command sarif-dockerfile-anchor rewrites Microsoft Defender (MDVM)
// container-image SARIF so that OS-package findings are anchored to the
// Dockerfile lines that introduced the packages, enabling GitHub code scanning
// pull-request inline annotations and diff gates.
//
// The original SARIF is never modified: the enriched document is written to
// stdout (or --output) and a one-line summary is written to stderr.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/anchor"
	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/cyclonedx"
	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/dockerfile"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("sarif-dockerfile-anchor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		sarifPath   = fs.String("sarif", "", "path to the Defender CLI image-scan SARIF (required)")
		sbomPath    = fs.String("sbom", "", "path to the CycloneDX SBOM JSON (required)")
		dfPath      = fs.String("dockerfile", "", "path to the Dockerfile to anchor findings to (required)")
		baseSevCSV  = fs.String("base-severity", "high,critical", "comma-separated severities of base-image OS findings kept inline")
		dfURI       = fs.String("dockerfile-uri", "", "repo-relative URI written into the SARIF artifactLocation (default: value of --dockerfile)")
		outputPath  = fs.String("output", "", "write the enriched SARIF here (default: stdout)")
		showVersion = fs.Bool("version", false, "print version and exit")
	)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "sarif-dockerfile-anchor %s\n\n", version)
		fmt.Fprintf(os.Stderr, "Anchor Microsoft Defender container-image SARIF findings to Dockerfile lines.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n  sarif-dockerfile-anchor --sarif <f> --sbom <f> --dockerfile <f> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println(version)
		return 0
	}

	var missing []string
	for flagName, val := range map[string]string{
		"--sarif":      *sarifPath,
		"--sbom":       *sbomPath,
		"--dockerfile": *dfPath,
	} {
		if val == "" {
			missing = append(missing, flagName)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "error: missing required flags: %s\n\n", strings.Join(missing, ", "))
		fs.Usage()
		return 2
	}

	// SARIF: decode into a generic document so unknown fields survive on output.
	sarifBytes, err := os.ReadFile(*sarifPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read sarif: %v\n", err)
		return 1
	}
	var doc map[string]any
	if err := json.Unmarshal(sarifBytes, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "error: parse sarif: %v\n", err)
		return 1
	}

	// SBOM: best-effort. Without it, no finding is classified as an OS package
	// and everything is left at the image reference.
	eco := cyclonedx.NewIndex(nil)
	if b, rerr := os.ReadFile(*sbomPath); rerr == nil {
		if idx, perr := cyclonedx.Parse(b); perr == nil {
			eco = idx
		} else {
			fmt.Fprintf(os.Stderr, "warning: parse sbom: %v (continuing without OS classification)\n", perr)
		}
	} else {
		fmt.Fprintf(os.Stderr, "warning: read sbom: %v (continuing without OS classification)\n", rerr)
	}

	dfBytes, err := os.ReadFile(*dfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read dockerfile: %v\n", err)
		return 1
	}
	df := dockerfile.Parse(string(dfBytes))

	uri := *dfURI
	if uri == "" {
		uri = *dfPath
	}

	cfg := anchor.Config{
		DockerfileURI:  uri,
		BaseFromLine:   df.FinalStageFromLine(),
		BaseSeverities: anchor.ParseSeverities(*baseSevCSV),
	}

	res := anchor.Enrich(doc, eco, df, cfg)

	out, err := json.Marshal(doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: serialize sarif: %v\n", err)
		return 1
	}
	if *outputPath == "" || *outputPath == "-" {
		if _, werr := os.Stdout.Write(append(out, '\n')); werr != nil {
			fmt.Fprintf(os.Stderr, "error: write output: %v\n", werr)
			return 1
		}
	} else if werr := os.WriteFile(*outputPath, out, 0o644); werr != nil {
		fmt.Fprintf(os.Stderr, "error: write output: %v\n", werr)
		return 1
	}

	fmt.Fprintf(os.Stderr, "anchor: injected=%d base(FROM)=%d left-at-image=%d\n",
		res.Injected, res.Base, res.Left)
	return 0
}
