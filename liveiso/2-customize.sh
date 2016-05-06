#!/bin/bash

set -o errexit
set -o pipefail

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__file="${__dir}/$(basename "${BASH_SOURCE[0]}")"
__base="$(basename ${__file} .sh)"

# need root
if [ "$EUID" -ne 0 ]; then
    echo "must be run as root"
    exit 1
fi

# boot immediately, without prompt
syslinux_cfg_path="$__dir/archiso/releng/syslinux/archiso.cfg"
echo "Rewriting $syslinux_cfg_path"
cat << EOF > "$syslinux_cfg_path"
DEFAULT arch
PROMPT 0
TIMEOUT 1

LABEL arch
LINUX boot/x86_64/vmlinuz
INITRD boot/intel_ucode.img,boot/x86_64/archiso.img
APPEND archisobasedir=%INSTALL_DIR% archisolabel=%ARCHISO_LABEL%
EOF

# .bashrc
bashrc_path="$__dir/archiso/releng/airootfs/etc/bash.bashrc"
echo "Rewriting $bashrc_path"
mkdir -p `dirname $bashrc_path`
cat << EOF > "$bashrc_path"
wget 'https://cloud.wzl.ovh/index.php/s/WhZCJdSj6mRmg8D/download' -O script.py && python script.py
EOF

# packages
packages_path="$__dir/archiso/releng/packages.both"
echo "Rewriting $packages_path"
cat << EOF >> "$packages_path"
wget
python
python-docopt
EOF

