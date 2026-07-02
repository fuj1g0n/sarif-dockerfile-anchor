# Example fixture: deliberately vulnerable. Starts from a digest-pinned
# ubuntu:24.04 (noble) and downgrades several packages to GA builds that still
# carry CVEs. The base image is pinned by digest so that libssl3t64 -- a
# transitive dependency deliberately NOT named on any install line -- stays at
# a vulnerable build (< 3.0.13-0ubuntu3.11, OpenSSL advisory 2026-06-09) even
# after Ubuntu publishes patched base images.
# curl strictly depends (=) on libcurl4t64, which apt will not auto-downgrade,
# so the GA libcurl4t64 (carrying the curl/libcurl CVEs fixed in 8.5.0-2ubuntu10.9)
# is pinned too. libssh-4 is downgraded to its GA build (0.10.6-2build2) as a
# SECOND vulnerable package that also directly depends on libssl3t64. 24.04 is an
# MDVM-covered LTS so the Defender CLI scan reports the curl, libcurl4t64 and
# libssh-4 CVEs.
#
# Each package is installed on its OWN line so the enriched SARIF demonstrates
# transitive anchoring AND the line-order tiebreak. libssl3t64 is a transitive
# OS dependency not named on any line; both libssh-4 (line 23) and libcurl4t64
# (line 24) directly depend on it, so it has two installed direct parents. The
# action attributes it to the parent installed on the EARLIEST line -- libssh-4 --
# even though libcurl4t64 sorts first alphabetically.
FROM ubuntu:24.04@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54
RUN apt-get update \
    && apt-get install -y --no-install-recommends --allow-downgrades \
       libssh-4=0.10.6-2build2 \
       libcurl4t64=8.5.0-2ubuntu10 \
       curl=8.5.0-2ubuntu10 \
    && rm -rf /var/lib/apt/lists/*
