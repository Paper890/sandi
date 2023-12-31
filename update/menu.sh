#!/bin/bash
# =========================================
UPDATE="https://raw.githubusercontent.com/Paper890/sandi/main/update/update.sh"
GREEN='\033[0;32m'
RED='\033[0;31m'
ipsaya=$(wget -qO- ipinfo.io/ip)
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
CITY=$(curl -s ipinfo.io/city )
MYIP=$(curl -sS ipv4.icanhazip.com)
# =========================================
vlx=$(grep -c -E "^#& " "/etc/xray/config.json")
let vla=$vlx/2
vmc=$(grep -c -E "^### " "/etc/xray/config.json")
let vma=$vmc/2
ssh1="$(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd | wc -l)"

trx=$(grep -c -E "^#! " "/etc/xray/config.json")
let tra=$trx/2
ssx=$(grep -c -E "^## " "/etc/xray/config.json")
let ssa=$ssx/2

UDPX="https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id=1S3IE25v_fyUfCLslnujFBSBMNunDHDk2' -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=1S3IE25v_fyUfCLslnujFBSBMNunDHDk2"
# // Exporting Language to UTF-8
export LC_ALL='en_US.UTF-8'
export LANG='en_US.UTF-8'
export LANGUAGE='en_US.UTF-8'
export LC_CTYPE='en_US.utf8'

# // Export Color & Information
export RED='\033[0;31m'
export GREEN='\033[0;32m'
export YELLOW='\033[0;33m'
export BLUE='\033[0;34m'
export PURPLE='\033[0;35m'
export CYAN='\033[0;36m'
export LIGHT='\033[0;37m'
export NC='\033[0m'

# // Export Banner Status Information
export EROR="[${RED} EROR ${NC}]"
export INFO="[${YELLOW} INFO ${NC}]"
export OKEY="[${GREEN} OKEY ${NC}]"
export PENDING="[${YELLOW} PENDING ${NC}]"
export SEND="[${YELLOW} SEND ${NC}]"
export RECEIVE="[${YELLOW} RECEIVE ${NC}]"

# // Export Align
export BOLD="\e[1m"
export WARNING="${RED}\e[5m"
export UNDERLINE="\e[4m"

# // Exporting URL Host
export Server_URL="autosc.me/aio"
export Server_Port="443"
export Server_IP="underfined"
export Script_Mode="Stable"
export Auther="FranataSTORE"

# // Root Checking
if [ "${EUID}" -ne 0 ]; then
                echo -e "${EROR} Please Run This Script As Root User !"
                exit 1
fi


# // Exporting IP Address
export IP=$( curl -s https://ipinfo.io/ip/ )

# // SSH Websocket Proxy
ssh_ws=$( systemctl status ws-epro | grep Active | awk '{print $3}' | sed 's/(//g' | sed 's/)//g' )
if [[ $ssh_ws == "running" ]]; then
    status_ws="${GREEN}ON${NC}"
else
    status_ws="${RED}OFF${NC}"
fi

# // nginx
nginx=$( systemctl status nginx | grep Active | awk '{print $3}' | sed 's/(//g' | sed 's/)//g' )
if [[ $nginx == "running" ]]; then
    status_nginx="${GREEN}ON${NC}"
else
    status_nginx="${RED}OFF${NC}"
fi

# // SSH Websocket Proxy
xray=$(/etc/init.d/ssh status | grep Active | awk '{print $3}' | cut -d "(" -f2 | cut -d ")" -f1)
if [[ $xray == "running" ]]; then
    status_xray="${GREEN}ON${NC}"
else
    status_xray="${RED}OFF${NC}"
fi

clear
clear
function add-host(){
clear
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
echo -e "$COLOR1│${NC} ${COLBG1}               • ADD VPS HOST •                ${NC} $COLOR1│$NC"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo -e "$COLOR1┌─────────────────────────────────────────────────┐${NC}"
read -rp "  New Host Name : " -e host
echo ""
if [ -z $host ]; then
echo -e "  [INFO] Type Your Domain/sub domain"
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo ""
read -n 1 -s -r -p "  Press any key to back on menu"
menu
else
echo "IP=$host" > /var/lib/ssnvpn-pro/ipvps.conf
echo ""
echo "  [INFO] Dont forget to renew cert"
echo ""
echo -e "$COLOR1└─────────────────────────────────────────────────┘${NC}"
echo ""
read -n 1 -s -r -p "  Press any key to Renew Cret"
crtxray
fi
}
clear
clear
echo -e "${GREEN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}                  .::: INFORMASI VPS :::.         ${NC}           "
echo -e "${GREEN}└─────────────────────────────────────────────────────┘${NC}"
echo -e "${CYAN}  • Sever Uptime${NC}      =${YELLOW} $( uptime -p  | cut -d " " -f 2-10000 )${NC} "
echo -e "${CYAN}  • Current Time${NC}      =${YELLOW} $( date -d "0 days" +"%d-%m-%Y | %X" )${NC}"
echo -e "${CYAN}  • Operating System${NC}  =${YELLOW} $( cat /etc/os-release | grep -w PRETTY_NAME | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g')( $(uname -m))${NC}"
echo -e "${CYAN}  • Current Domain${NC}    =${YELLOW} $( cat /etc/xray/domain )${NC}"
echo -e "${CYAN}  • Server IP${NC}         =${YELLOW} ${MYIP} ${NC}"
echo -e "${CYAN}  • ISP-VPS${NC}           =${YELLOW} ${ISP} ${NC}"
echo -e "${CYAN}  • City${NC}              =${YELLOW} ${CITY} ${NC}"
echo -e "${CYAN}  • Clients Name${NC}      =${LIGHT} Power Rangger Merah ${NC}"
echo -e "${CYAN}  • Script Exfire${NC}     =${RED} Lifetime ${NC}"
echo -e "${GREEN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${GREEN}    [ SSH Ws: ${GREEN}ON${NC} ]    [ NGINX: ${status_nginx} ]   [ XRAY : ${status_xray} ] "
echo -e "${GREEN}└─────────────────────────────────────────────────────┘${NC}"
echo -e "${GREEN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}      SSH     VMESS     VLESS     TROJAN     SDSK ${NC}"
echo -e "${YELLOW}       $ssh1        $vma         $vla          $tra         $ssa ${NC}"
echo -e "${GREEN}└─────────────────────────────────────────────────────┘${NC}"
echo -e "${GREEN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}                 .::: MENU TUNNELING :::.                   ${NC} "
echo -e "${GREEN}└─────────────────────────────────────────────────────┘${NC}"
echo -e "${CYAN}    ${YELLOW}1.${NC} ${CYAN}SSH OVPN MANAGER${NC}         ${YELLOW}6.${NC} ${CYAN}BACKUP/RESTORE ${NC}"
echo -e "${CYAN}    ${YELLOW}2.${NC} ${CYAN}VMESS MANAGER${NC}            ${YELLOW}7.${NC} ${CYAN}SETTING  ${NC}"
echo -e "${CYAN}    ${YELLOW}3.${NC} ${CYAN}VLESS MANAGER${NC}            ${YELLOW}8.${NC} ${CYAN}UPDATE SCRIPT   ${NC} "
echo -e "${CYAN}    ${YELLOW}4.${NC} ${CYAN}TROJAN MANAGER${NC}           ${YELLOW}9.${NC} ${CYAN}ADD HOST/DOMAIN   ${NC} "
echo -e "${CYAN}    ${YELLOW}5.${NC} ${CYAN}SHODOWSOK MANAGER${NC}       ${YELLOW}10.${NC} ${CYAN}INSTALL/FIX UDP  ${NC} "
echo -e "${GREEN}┌─────────────────────────────────────────────────────┐${NC}"
echo -e "${CYAN}              .::: AUTOSCRIPT SIMPLE :::.                    ${NC} "
echo -e "${GREEN}└─────────────────────────────────────────────────────┘${NC}"
echo ""
echo -ne " Select menu : "; read opt
case $opt in
01 | 1) clear ; menu-ssh ;;
02 | 2) clear ; menu-vmess ;;
03 | 3) clear ; menu-vless ;;
04 | 4) clear ; menu-trojan ;;
05 | 5) clear ; menu-ss ;;
06 | 6) clear ; menu-backup ;;
07 | 7) clear ; menu-set ;;
08 | 8) clear ; wget ${UPDATE} && chmod +x update.sh && ./update.sh ;;
09 | 9) clear ; add-host ;;
10 | 10) clear ; wget https://raw.githubusercontent.com/Paper890/sandi/main/update/udp-custom.sh && chmod +x udp-custom.sh && ./udp-custom.sh ;;
999) clear ; $up2u ;;
00 | 0) clear ; menu ;;
*) clear ; menu ;;
esac
