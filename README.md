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
| **Transitive** OS package | not named in the Dockerfile, but in the SBOM dependency closure of an injected package | the nearest such install line (any severity; `--link-transitive`, default on) |
| **Base-image** OS package | OS package not present in the Dockerfile (and no injected ancestor) | the final-stage `FROM` line (kept only for `--base-severity`) |
| **Application / language** package | SBOM `purl` type is not an OS/distro type (e.g. `pkg:maven/…`, `pkg:npm/…`) | left at the image reference (Dependabot / CodeQL territory) |

- OS vs application is decided from the CycloneDX SBOM `purl` **type**: the
  distro/system types `deb`, `rpm`, `apk`, `alpm`, `qpkg`, `yocto`
  ([purl spec](https://github.com/package-url/purl-spec/tree/main/types)) are
  treated as OS packages; everything else (`maven`, `npm`, `pypi`, `golang`,
  `nuget`, `conda`, `conan`, `generic`, …) is application/language.
- Base-image findings anchor to the Dockerfile's **final-stage `FROM`** (the last
  `FROM`), since the scanned image is always built from that stage — no base
  image needs to be supplied.
- **Transitive** anchoring (`--link-transitive`, default on) walks the CycloneDX
  `dependencies` graph: an OS finding not named in the Dockerfile is anchored to
  the install line of the *nearest* package that pulled it in, instead of the
  `FROM` line. A package in an installed package's dependency **closure** is thus
  attributed to that install line — including shared base libraries it depends
  on. Pass `--link-transitive=false` to keep the base-`FROM` behaviour.
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
# summary (injected / transitive / base / left-at-image counts) is printed to stderr
```

| Flag | Required | Default | Description |
|---|---|---|---|
| `--sarif` | yes | | Defender CLI image-scan SARIF |
| `--sbom` | yes | | CycloneDX SBOM JSON (OS/app classification via `purl`) |
| `--dockerfile` | yes | | Dockerfile to anchor findings to |
| `--base-severity` | no | `high,critical` | severities of base-image OS findings kept inline |
| `--link-transitive` | no | `true` | anchor a transitive OS finding to the install line of the nearest package (per the SBOM dependency graph) that pulled it in; `false` keeps the base-`FROM` behaviour |
| `--dockerfile-uri` | no | value of `--dockerfile` | repo-relative URI written into the SARIF; override **only** when the file read differs from its committed path (e.g. an absolute `--dockerfile`, or a generated/rendered Dockerfile) |
| `--output` | no | stdout | where to write the enriched SARIF |

### Inputs from the Defender CLI

The [Defender for Cloud CLI][dcli] produces these files (verified with CLI
v2.0.3334.114):

```sh
# Export the locally-built image to a docker-archive tar first. The Defender
# CLI resolver only accepts a local artifact (OCI layout dir / tar) or a
# pullable registry reference; a bare local-daemon tag logs
# "pkg/resolver : No suitable resolver found". A tar resolves cleanly.
docker save "$IMAGE" -o image.tar

# Image scan (--scanner mdvm): vulnerability findings from Microsoft Defender
# Vulnerability Management. --defender-output names its scan SARIF (default:
# defender.sarif in the working directory).
defender scan image image.tar --scanner mdvm     --defender-output image.sarif

# SBOM scan (--scanner mdvmsbom): --defender-output names its scan SARIF, which
# reports malicious packages (same default defender.sarif). --output names the
# CycloneDX SBOM file with OS/app purls used for classification (default
# sbom-finding-<timestamp>.json; --sbom-format default cyclonedx1.6-json).
defender scan sbom  image.tar --scanner mdvmsbom --defender-output sbom.sarif --output sbom.cyclonedx.json
```

> [!IMPORTANT]
> `defender scan image` and `defender scan sbom` BOTH default their scan SARIF to
> `defender.sarif` in the working directory (the `--defender-output` default). Run
> in the same directory without distinct names, they overwrite each other — the
> SBOM scan (which reports malicious packages, usually none) would clobber the
> image scan's vulnerabilities with an empty SARIF. Give each scan a distinct
> `--defender-output` (`image.sarif` / `sbom.sarif`) and pin the scanner
> explicitly — `--scanner mdvm` for the image scan (vulnerabilities) and
> `--scanner mdvmsbom` for the SBOM scan — so the SARIF content stays
> deterministic regardless of CLI default changes or invocation order.

> [!NOTE]
> The exported image SARIF holds Critical/High/Medium findings; Low-severity
> findings are excluded by default in the tested CLI version. All findings are
> located at the image reference (line 1) — which is exactly what this tool remaps.

[dcli]: https://learn.microsoft.com/azure/defender-for-cloud/defender-cli-syntax

## GitHub Actions usage

```yaml
- name: Defender for Cloud image scan + SBOM
  run: |
    # Scan a docker-archive tar (docker save), not the bare local-daemon tag:
    # the resolver only accepts a local artifact (tar / OCI dir) or a pullable
    # registry ref, so a bare tag logs "No suitable resolver found".
    # Pin the scanner explicitly and give each scan a distinct --defender-output;
    # both scan SARIFs default to defender.sarif and would otherwise overwrite
    # each other regardless of order.
    docker save "$IMAGE" -o image.tar
    ./defender scan image image.tar --scanner mdvm     --defender-output image.sarif
    ./defender scan sbom  image.tar --scanner mdvmsbom --defender-output sbom.sarif --output sbom.cyclonedx.json

- name: Anchor MDVM SARIF to Dockerfile
  id: anchor
  uses: fuj1g0n/sarif-dockerfile-anchor@v1
  with:
    sarif: image.sarif
    sbom: sbom.cyclonedx.json
    dockerfile: Dockerfile
    output: image.enriched.sarif
    # link-transitive: true  # (default) anchor transitive OS deps to their
    #                        # introducing install line; false keeps base-FROM

- name: Upload to code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ${{ steps.anchor.outputs.sarif }}
    category: defender-mdvm
```

When pinned to a release tag (`@vX.Y.Z`) the composite action downloads the
matching prebuilt binary for the runner's OS/architecture. When pinned to any
other ref (`@main`, a branch, or a SHA) it builds the binary from the action
source at that exact commit, using the same devbox-pinned Go toolchain as CI, so
behaviour is tied to the pinned commit. No Python or other runtime is required.

## Development

This repo uses [devbox](https://www.jetify.com/devbox) for a reproducible Go
toolchain:

```sh
devbox run -- go test ./...
devbox run -- go build ./...
```

## License

[Apache-2.0](LICENSE)
