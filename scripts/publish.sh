#!/usr/bin/env bash

# Exit on error or on unset variable
set -eu

. ./scripts/base.sh

${CONTAINER_COMMAND} push ${IMAGE_URI}
