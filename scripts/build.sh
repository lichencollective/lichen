#!/usr/bin/env bash

# Exit on error or on unset variable
set -eu

. ./scripts/base.sh

${CONTAINER_COMMAND} build --pull --no-cache -f Containerfile -t ${IMAGE_URI} .
