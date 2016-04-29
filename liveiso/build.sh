#!/bin/bash

set -o errexit
set -o pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__file="${__dir}/$(basename "${BASH_SOURCE[0]}")"
__base="$(basename ${__file} .sh)"

docker build -t archiso - < "$__dir/Dockerfile"

archiso="$__dir/archiso"

# build iso
docker run \
    -ti \
    --rm \
    --privileged \
    -v "$archiso":/archiso \
    archiso \
    /bin/bash -c 'cd /archiso/baseline && ./build.sh -v'
