
Debian
====================
This directory contains files used to package bcod/bco-qt
for Debian-based Linux systems. If you compile bcod/bco-qt yourself, there are some useful files here.

## bco: URI support ##


bco-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install bco-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your bco-qt binary to `/usr/bin`
and the `../../share/pixmaps/bco128.png` to `/usr/share/pixmaps`

bco-qt.protocol (KDE)

