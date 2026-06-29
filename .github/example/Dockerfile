# Example fixture: deliberately vulnerable. Starts from the latest ubuntu:24.04
# (noble) and downgrades curl to its GA build (8.5.0-2ubuntu10). curl strictly
# depends (=) on libcurl4t64, which apt will not auto-downgrade, so the GA
# libcurl4t64 (carrying the curl/libcurl CVEs fixed in 8.5.0-2ubuntu10.9) is
# pinned here too. 24.04 is an MDVM-covered LTS so the Defender CLI scan reports
# the curl and libcurl4t64 CVEs.
FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends --allow-downgrades \
       curl=8.5.0-2ubuntu10 libcurl4t64=8.5.0-2ubuntu10 \
    && rm -rf /var/lib/apt/lists/*
