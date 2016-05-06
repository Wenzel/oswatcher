FROM greyltc/archlinux

RUN cp /etc/pacman.d/mirrorlist /etc/pacman.d/mirrorlist.backup
RUN rankmirrors -n 5 -v /etc/pacman.d/mirrorlist.backup > /etc/pacman.d/mirrorlist
RUN pacman -Syu --noconfirm
RUN pacman-db-upgrade
RUN pacman -S --noconfirm archiso
# RUN useradd -ms /bin/bash docker
VOLUME /archiso
CMD /bin/bash
