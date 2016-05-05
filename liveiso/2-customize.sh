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

# autologin
getty_service_path="$__dir/archiso/baseline/work/airootfs/etc/systemd/system/getty.target.wants/getty@tty1.service"
echo "Rewriting $getty_service_path"
mkdir -p `dirname $getty_service_path`
cat << EOF > "$getty_service_path"
[Unit]
Description=Getty on %I
Documentation=man:agetty(8) man:systemd-getty-generator(8)
Documentation=http://0pointer.de/blog/projects/serial-console.html
After=systemd-user-sessions.service plymouth-quit-wait.service
After=rc-local.service

# If additional gettys are spawned during boot then we should make
# sure that this is synchronized before getty.target, even though
# getty.target didn't actually pull it in.
Before=getty.target
IgnoreOnIsolate=yes

# On systems without virtual consoles, don't start any getty. Note
# that serial gettys are covered by serial-getty@.service, not this
# unit.
ConditionPathExists=/dev/tty0

[Service]
# the VT is cleared by TTYVTDisallocate
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
Type=idle
Restart=always
RestartSec=0
UtmpIdentifier=%I
TTYPath=/dev/%I
TTYReset=yes
TTYVHangup=yes
TTYVTDisallocate=yes
KillMode=process
IgnoreSIGPIPE=no
SendSIGHUP=yes

# Unset locale for the console getty since the console has problems
# displaying some internationalized messages.
Environment=LANG= LANGUAGE= LC_CTYPE= LC_NUMERIC= LC_TIME= LC_COLLATE= LC_MONETARY= LC_MESSAGES= LC_PAPER= LC_NAME= LC_ADDRESS= LC_TELEPHONE= LC_MEASUREMENT= LC_IDENTIFICATION=

[Install]
WantedBy=getty.target
DefaultInstance=tty1
EOF
