domain=$(cat /etc/xray/domain)
tls="$(cat ~/log-install.txt | grep -w "Vless TLS" | cut -d: -f2|sed 's/ //g')"
none="$(cat ~/log-install.txt | grep -w "Vless None TLS" | cut -d: -f2|sed 's/ //g')"
user=vless`</dev/urandom tr -dc X-Z0-9 | head -c4`
uuid=$(cat /proc/sys/kernel/random/uuid)
masaaktif=35
exp=`date -d "$masaaktif days" +"%Y-%m-%d"`
sed -i '/#vless$/a\#& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
sed -i '/#vlessgrpc$/a\#& '"$user $exp"'\
},{"id": "'""$uuid""'","email": "'""$user""'"' /etc/xray/config.json
vlesslink1="vless://${uuid}@${domain}:$tls?path=/vlessws&security=tls&encryption=none&type=ws#${user}"
vlesslink2="vless://${uuid}@${domain}:$none?path=/vlessws&encryption=none&type=ws#${user}"
vlesslink3="vless://${uuid}@${domain}:$tls?mode=gun&security=tls&encryption=none&type=grpc&serviceName=vless-grpc&sni=bug.com#${user}"
systemctl restart xray
clear
cat << 'EOF' > /root/san/bot/buyvpn/akun/vless.txt
━━━━━━━━━━━━━━━━━━━━━━━━━━━
   • CREATE VLESS USER •    
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Remarks       : ${user}
Expired On    : $exp
Domain        : ${domain}
port TLS      : $tls
port none TLS : $none
id            : ${uuid}
Encryption    : none
Network       : ws
Path          : /vless
Path WSS      : wss://bug.com/vless
Path          : vless-grpc
━━━━━━━━━━━━━━━━━━━━━━━━━━━
Link TLS :
${vlesslink1}

Link none TLS : 
${vlesslink2}

Link GRPC : 
${vlesslink3}
━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
