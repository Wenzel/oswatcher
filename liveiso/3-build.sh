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
    /bin/bash -c 'cd /archiso/releng && ./build.sh -v && mv /archiso/releng/out/* /archiso/releng/out/live.iso && chown 1000:1000 -R /archiso/releng/out'
