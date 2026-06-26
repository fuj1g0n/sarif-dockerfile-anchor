# sarif-dockerfile-anchor

Anchor [Microsoft Defender Vulnerability Management (MDVM)][mdvm] container-image
SARIF findings to the **Dockerfile lines** that introduced the vulnerable
packages, so [GitHub code scanning][cs] renders them as pull-request **inline
annotations** and **diff gates** — the same experience CodeQL gives on source
code.

Defender for Cloud's container scan reports every finding at the *image
reference* (for example `myregistry.azurecr.io/app` line 1). GitHub code
scanning can only annotate a pull request on a **changed line of a file in the
repository**, so those findings never appear inline on the PR diff. This tool
rewrites each OS-package finding's location to the Dockerfile instruction that
introduced the package.

> Generalized, reusable port of an internal remap script. Single tool, no extra
> services; reads the SARIF + a CycloneDX SBOM + your Dockerfile.

[mdvm]: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-vulnerability-assessment-azure
[cs]: https://docs.github.com/code-security/code-scanning

## How it classifies findings

| Finding kind | Decided by | Anchored to |
|---|---|---|
| **Injected** OS package | name appears in the Dockerfile as a `<name>_…deb` filename or `<name>=` apt pin | the install/download line (any severity) |
| **Base-image** OS package | OS package not present in the Dockerfile | the final-stage `FROM` line (kept only for `--base-severity`) |
| **Application / language** package | SBOM `purl` is not `pkg:deb/…` (e.g. `pkg:maven/…`) | left at the image reference (Dependabot / CodeQL territory) |

- OS vs application is read from the CycloneDX SBOM `purl` ecosystem.
- Base-image findings anchor to the Dockerfile's **final-stage `FROM`** (the last
  `FROM`), since the scanned image is always built from that stage — no base
  image needs to be supplied.
- A stable `partialFingerprints` (`sha1(ruleId + package)`) keeps alerts from
  churning across re-runs.

The original SARIF is **never modified**: the enriched document is written to
stdout (or `--output`) and a one-line summary goes to stderr.

## Install

Download a prebuilt static binary from the [releases page][rel], or build from
source:

```sh
go install github.com/fuj1g0n/sarif-dockerfile-anchor/cmd/sarif-dockerfile-anchor@latest
```

[rel]: https://github.com/fuj1g0n/sarif-dockerfile-anchor/releases

## CLI usage

The input files come from the Defender for Cloud CLI (see
[Inputs from the Defender CLI](#inputs-from-the-defender-cli)):

```sh
sarif-dockerfile-anchor \
  --sarif        image.sarif \
  --sbom         sbom.cyclonedx.json \
  --dockerfile   Dockerfile \
  --output       image.enriched.sarif
# summary (injected / base / left-at-image counts) is printed to stderr
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--sarif` | yes | | Defender CLI image-scan SARIF |
| `--sbom` | yes | | CycloneDX SBOM JSON (OS/app classification via `purl`) |
| `--dockerfile` | yes | | Dockerfile to anchor findings to |
| `--base-severity` | no | `high,critical` | severities of base-image OS findings kept inline |
| `--dockerfile-uri` | no | value of `--dockerfile` | repo-relative URI written into the SARIF; override **only** when the file read differs from its committed path (e.g. an absolute `--dockerfile`, or a generated/rendered Dockerfile) |
| `--output` | no | stdout | where to write the enriched SARIF |

### Inputs from the Defender CLI

The [Defender for Cloud CLI][dcli] produces these files (verified with CLI
v2.0.3334.114):

```sh
# Image scan: writes its scan SARIF to --defender-output (default: defender.sarif
# in the working directory). Give it an explicit name so the SBOM scan below
# cannot overwrite it.
defender scan image "$IMAGE" --defender-output image.sarif

# SBOM scan: --output names the CycloneDX file (default sbom-finding-<timestamp>.json,
# timestamp YYYYMMDD-HHMMSS; --sbom-format default cyclonedx1.6-json).
defender scan sbom "$IMAGE" --output sbom.cyclonedx.json
```

> [!IMPORTANT]
> `defender scan image` and `defender scan sbom` BOTH default their scan SARIF to
> `defender.sarif` in the working directory (the `--defender-output` default). Run
> in the same directory without distinct names, the SBOM scan (which reports
> malicious packages — usually none) overwrites the image scan's SARIF with an
> empty one. Always give the image scan an explicit `--defender-output`.

> [!NOTE]
> The exported image SARIF holds Critical/High/Medium findings; Low-severity
> findings are excluded by default in the tested CLI version. All findings are
> located at the image reference (line 1) — which is exactly what this tool remaps.

[dcli]: https://learn.microsoft.com/azure/defender-for-cloud/defender-cli-syntax

## GitHub Actions usage

```yaml
- name: Defender for Cloud image scan + SBOM
  run: |
    # Give the image scan a distinct --defender-output; the SBOM scan's own scan
    # SARIF also defaults to defender.sarif and would otherwise overwrite it.
    ./defender scan image "$IMAGE" --defender-output image.sarif
    ./defender scan sbom  "$IMAGE" --output sbom.cyclonedx.json

- name: Anchor MDVM SARIF to Dockerfile
  id: anchor
  uses: fuj1g0n/sarif-dockerfile-anchor@v1
  with:
    sarif: image.sarif
    sbom: sbom.cyclonedx.json
    dockerfile: Dockerfile
    output: image.enriched.sarif

- name: Upload to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.anchor.outputs.sarif }}
    category: defender-mdvm
```

The composite action downloads the matching release binary for the runner's
OS/architecture; no Python or other runtime is required on the runner.

## Development

This repo uses [devbox](https://www.jetify.com/devbox) for a reproducible Go
toolchain:

```sh
devbox run -- go test ./...
devbox run -- go build ./...
```

## License

[Apache-2.0](LICENSE)
