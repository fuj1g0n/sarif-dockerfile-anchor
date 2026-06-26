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
	"fmt"
	"os"
	"strings"

	"github.com/alecthomas/kong"

	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/anchor"
	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/cyclonedx"
	"github.com/fuj1g0n/sarif-dockerfile-anchor/internal/dockerfile"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

// cli is the kong command-line grammar. Each exported field is a flag; the
// flag name is derived from the field name (kebab-case) unless overridden.
type cli struct {
	Sarif         string `help:"Path to the Defender CLI image-scan SARIF (required)." placeholder:"FILE"`
	Sbom          string `help:"Path to the CycloneDX SBOM JSON (required)." placeholder:"FILE"`
	Dockerfile    string `help:"Path to the Dockerfile to anchor findings to (required)." placeholder:"FILE"`
	BaseSeverity  string `help:"Comma-separated severities of base-image OS findings kept inline." default:"high,critical"`
	DockerfileURI string `name:"dockerfile-uri" help:"Repo-relative URI written into the SARIF (default: value of --dockerfile)." placeholder:"PATH"`
	Output        string `short:"o" help:"Write the enriched SARIF here (default: stdout)." placeholder:"FILE"`
	Version       bool   `help:"Print version and exit."`
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	var c cli
	parser, err := kong.New(&c,
		kong.Name("sarif-dockerfile-anchor"),
		kong.Description("Anchor Microsoft Defender container-image SARIF findings to Dockerfile lines."),
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if _, perr := parser.Parse(args); perr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", perr)
		return 2
	}
	if c.Version {
		fmt.Println(version)
		return 0
	}

	// --sarif/--sbom/--dockerfile are required. They are validated here rather
	// than via kong's "required" tag so that --version short-circuits cleanly.
	var missing []string
	for flagName, val := range map[string]string{
		"--sarif":      c.Sarif,
		"--sbom":       c.Sbom,
		"--dockerfile": c.Dockerfile,
	} {
		if val == "" {
			missing = append(missing, flagName)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "error: missing required flags: %s\n", strings.Join(missing, ", "))
		return 2
	}

	// SARIF: decode into a generic document so unknown fields survive on output.
	sarifBytes, err := os.ReadFile(c.Sarif)
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
	if b, rerr := os.ReadFile(c.Sbom); rerr == nil {
		if idx, perr := cyclonedx.Parse(b); perr == nil {
			eco = idx
		} else {
			fmt.Fprintf(os.Stderr, "warning: parse sbom: %v (continuing without OS classification)\n", perr)
		}
	} else {
		fmt.Fprintf(os.Stderr, "warning: read sbom: %v (continuing without OS classification)\n", rerr)
	}

	dfBytes, err := os.ReadFile(c.Dockerfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: read dockerfile: %v\n", err)
		return 1
	}
	df := dockerfile.Parse(string(dfBytes))

	uri := c.DockerfileURI
	if uri == "" {
		uri = c.Dockerfile
	}

	cfg := anchor.Config{
		DockerfileURI:  uri,
		BaseFromLine:   df.FinalStageFromLine(),
		BaseSeverities: anchor.ParseSeverities(c.BaseSeverity),
	}

	res := anchor.Enrich(doc, eco, df, cfg)

	out, err := json.Marshal(doc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: serialize sarif: %v\n", err)
		return 1
	}
	if c.Output == "" || c.Output == "-" {
		if _, werr := os.Stdout.Write(append(out, '\n')); werr != nil {
			fmt.Fprintf(os.Stderr, "error: write output: %v\n", werr)
			return 1
		}
	} else if werr := os.WriteFile(c.Output, out, 0o644); werr != nil {
		fmt.Fprintf(os.Stderr, "error: write output: %v\n", werr)
		return 1
	}

	fmt.Fprintf(os.Stderr, "anchor: injected=%d base(FROM)=%d left-at-image=%d\n",
		res.Injected, res.Base, res.Left)
	return 0
}
