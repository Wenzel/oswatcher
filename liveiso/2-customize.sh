#!/bin/bash

set -o errexit
set -o pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__file="${__dir}/$(basename "${BASH_SOURCE[0]}")"
__base="$(basename ${__file} .sh)"

# # need root
# if [ "$EUID" -ne 0 ]; then
#     echo "must be run as root"
#     exit 1
# fi

# boot immediately, without prompt
syslinux_cfg_path="$__dir/archiso/baseline/syslinux/syslinux.cfg"
echo "Rewriting $syslinux_cfg_path"
cat << EOF > "$syslinux_cfg_path"
DEFAULT arch
PROMPT 0
TIMEOUT 1

LABEL arch
LINUX boot/%ARCH%/vmlinuz
INITRD boot/%ARCH%/archiso.img
APPEND archisobasedir=%INSTALL_DIR% archisolabel=%ARCHISO_LABEL%
EOF
