#!/usr/bin/env bash

set -euo pipefail

mkdir output || :

ampel verify "$(crane manifest ghcr.io/puerco/mild-to-wild-samples | jq -r '.annotations["org.opencontainers.image.base.digest"]')" \
   -p 1-mild/ampel/verify-base.hjson \
   -c coci:registry.access.redhat.com/ubi10/ubi-minimal:latest \
   -x 'buildPoint:git+https://gitlab.com/redhat/rhel/containers/ubi10-minimal.git' \
   --attest-format vsa \
   --attest-results=true \
   --results-path=output/base.vsa.json
