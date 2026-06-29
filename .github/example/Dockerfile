# Example fixture: a deliberately vulnerable image so the Defender CLI scan
# returns OS-package findings the action can anchor. The injected `curl` install
# line is what base/injected anchoring is verified against.
FROM ubuntu:22.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*
