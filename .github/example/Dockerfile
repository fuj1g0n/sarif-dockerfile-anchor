# Example fixture: latest LTS base, fully patched. apt-get upgrade pulls the
# newest package versions so the Defender CLI scan reports few/no OS-package
# findings. A follow-up PR can introduce vulnerabilities to demonstrate the
# anchored annotations on the Dockerfile.
FROM ubuntu:26.04
RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/*
