#!/bin/bash

set -o errexit
set -o pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__file="${__dir}/$(basename "${BASH_SOURCE[0]}")"
__base="$(basename ${__file} .sh)"

docker build -t archiso - < "$__dir/Dockerfile"

archiso="$__dir/archiso"

# removing old archiso
echo "Removing old archiso directory"
rm -rf "$archiso"

# generate skeleton
mkdir -p "$archiso"
docker run \
    -ti \
    -u docker \
    --rm \
    --privileged \
    -v "$archiso":/archiso \
    archiso \
    /bin/bash -c 'cp -r /usr/share/archiso/configs/baseline/ /archiso'
