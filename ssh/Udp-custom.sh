#!/bin/bash
#
# ==================================================

#Install UDP Custom
sudo -s
clear; wget --no-check-certificate "https://raw.githubusercontent.com/prjkt-nv404/UDP-Custom-Installer-arm64/main/udpc-installer.sh" -O udpc-installer.sh && chmod +x udpc-installer.sh && ./udpc-installer.sh
./udpc-installer.sh
