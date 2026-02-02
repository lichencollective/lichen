#!/usr/bin/env bash

# Exit on error or on unset variable
set -eu

if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
fi

ENVIRONMENT="${TF_VAR_environment:-development}"
OCI_REPOSITORY="${TF_VAR_oci_repository:-localhost}"
TIMESTAMP="$(TZ=UTC date +%Y-%m-%dT%H_%M_%SZ)" # ISO 8601, but replaced ":" for "_" for docker compatibility
IMAGE_TAG="${IMAGE_TAG:-latest-$TIMESTAMP}"
IMAGE_URI=${IMAGE_URI:-${OCI_REPOSITORY}/frontend-${ENVIRONMENT}:${IMAGE_TAG}}
DEPLOY="${DEPLOY:-false}"
DOCKER_BUILDKIT=1
BUILDKIT_PROGRESS=plain

# check if CONTAINER_COMMAND is already set, if not, set it to docker
CONTAINER_COMMAND=${CONTAINER_COMMAND:-podman}
