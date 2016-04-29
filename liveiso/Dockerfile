FROM greyltc/archlinux

RUN pacman -Syu --noconfirm
RUN pacman-db-upgrade
RUN pacman -S --noconfirm archiso
VOLUME /archiso
CMD /bin/bash
