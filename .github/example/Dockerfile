# Example fixture: deliberately vulnerable. Starts from the latest ubuntu:24.04
# (noble) and downgrades curl to its GA build (8.5.0-2ubuntu10). curl strictly
# depends (=) on libcurl4t64, which apt will not auto-downgrade, so the GA
# libcurl4t64 (carrying the curl/libcurl CVEs fixed in 8.5.0-2ubuntu10.9) is
# pinned here too. 24.04 is an MDVM-covered LTS so the Defender CLI scan reports
# the curl and libcurl4t64 CVEs.
#
# libcurl4t64 and curl are installed on SEPARATE lines so the enriched SARIF
# demonstrates transitive anchoring. libssl3t64 is a transitive OS dependency
# that is not named on any line; it anchors to the libcurl4t64 install line --
# its nearest installed ancestor in the SBOM dependency graph -- and NOT the
# curl line, because curl reaches libssl3t64 only indirectly via libcurl4t64.
FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends --allow-downgrades \
       libcurl4t64=8.5.0-2ubuntu10 \
    && apt-get install -y --no-install-recommends --allow-downgrades \
       curl=8.5.0-2ubuntu10 \
    && rm -rf /var/lib/apt/lists/*
