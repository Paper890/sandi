#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
#########################

clear
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;33m'
NC='\e[0m'
echo "XRAY Core Vmess / Vless"
echo "Trojan"
echo "Progress..."
sleep 3
#"
date
echo ""
domain=$(cat /root/domain)
sleep 1
mkdir -p /etc/xray 
echo -e "[ ${green}INFO${NC} ] Checking... "
apt install iptables iptables-persistent -y
sleep 1
echo -e "[ ${green}INFO$NC ] Setting ntpdate"
ntpdate pool.ntp.org 
timedatectl set-ntp true
sleep 1
echo -e "[ ${green}INFO$NC ] Enable chronyd"
systemctl enable chronyd
systemctl restart chronyd
sleep 1
echo -e "[ ${green}INFO$NC ] Enable chrony"
systemctl enable chrony
systemctl restart chrony
timedatectl set-timezone Asia/Kuala_Lumpur
sleep 1
echo -e "[ ${green}INFO$NC ] Setting chrony tracking"
chronyc sourcestats -v
chronyc tracking -v
echo -e "[ ${green}INFO$NC ] Setting dll"
apt clean all && apt update
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion ntpdate -y
ntpdate pool.ntp.org
apt -y install chrony
apt install zip -y
apt install curl pwgen openssl netcat cron -y


# install xray
sleep 1
echo -e "[ ${green}INFO$NC ] Downloading & Installing xray core"
domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
chown www-data.www-data $domainSock_dir
# Make Folder XRay
mkdir -p /var/log/xray
mkdir -p /etc/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
touch /var/log/xray/access2.log
touch /var/log/xray/error2.log
# / / Ambil Xray Core Version Terbaru

# Ambil Xray Core Version Terbaru
latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
# Installation Xray Core
# $latest_version
xraycore_link="https://github.com/XTLS/Xray-core/releases/download/v1.7.5/xray-linux-64.zip"
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version

## crt xray
systemctl stop nginx
mkdir /root/.acme.sh
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --upgrade --auto-upgrade
/root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc

# nginx renew ssl
echo -n '#!/bin/bash
/etc/init.d/nginx stop
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /root/renew_ssl.log
/etc/init.d/nginx start
' > /usr/local/bin/ssl_renew.sh
chmod +x /usr/local/bin/ssl_renew.sh
if ! grep -q 'ssl_renew.sh' /var/spool/cron/crontabs/root;then (crontab -l;echo "15 03 */3 * * /usr/local/bin/ssl_renew.sh") | crontab;fi

mkdir -p /home/vps/public_html

# set uuid
uuid=$(cat /proc/sys/kernel/random/uuid)
# xray config
cat > /etc/xray/config.json << END
  {
  "log": {
    "loglevel": "warning",
    "error": "/var/log/xray/error.log",
    "access": "/var/log/xray/access.log"
   },
   "api": {
    "services": [
      "HandlerService",
      "LoggerService",
      "StatsService"
     ],
    "tag": "api"
    },
    "stats": {},
    "policy": {
    "levels": {
      "0": {
        "handshake": 2,
        "connIdle": 128,
        "statsUserUplink": true,
        "statsUserDownlink": true
        }
       }
      },
      "inbounds": [
      {
      "listen": "127.0.0.1",
      "port": 10000,
      "protocol": "dokodemo-door",
      "settings": {
        "address": "127.0.0.1"
      },
      "tag": "api"
      },
      {
     "listen": "127.0.0.1",
     "port": "10001",
     "protocol": "vless",
      "settings": {
          "decryption":"none",
            "clients": [
               {
                 "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
#vless
             }
          ]
       },
       "streamSettings":{
         "network": "ws",
            "wsSettings": {
                "path": "/vless"
          }
        }
     },
     {
     "listen": "127.0.0.1",
     "port": "10002",
     "protocol": "vmess",
      "settings": {
            "clients": [
               {
                 "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0",
                 "alterId": 0
#vmess
             }
          ]
       },
       "streamSettings":{
         "network": "ws",
            "wsSettings": {
                "path": "/vmess"
           }
         }
       },
       {
      "listen": "127.0.0.1",
      "port": "10003",
      "protocol": "trojan",
      "settings": {
          "decryption":"none",
           "clients": [
              {
                 "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
#trojanws
              }
          ],
         "udp": true
       },
       "streamSettings":{
           "network": "ws",
           "wsSettings": {
               "path": "/trojan-ws"
            }
         }
     },
      {
         "listen": "127.0.0.1",
        "port": "10004",
        "protocol": "shadowsocks",
        "settings": {
           "clients": [
           {
           "method": "aes-128-gcm",
          "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
#ssws
           }
          ],
          "network": "tcp,udp"
       },
       "streamSettings":{
          "network": "ws",
             "wsSettings": {
               "path": "/ss-ws"
           }
        }
     },
      {
        "listen": "127.0.0.1",
        "port": "10005",
        "protocol": "vless",
        "settings": {
         "decryption":"none",
           "clients": [
             {
               "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
#vlessgrpc
             }
          ]
       },
          "streamSettings":{
             "network": "grpc",
             "grpcSettings": {
                "serviceName": "vless-grpc"
           }
        }
     },
     {
      "listen": "127.0.0.1",
      "port": "10006",
     "protocol": "vmess",
      "settings": {
            "clients": [
               {
                 "id": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0",
                 "alterId": 0
#vmessgrpc
             }
          ]
       },
       "streamSettings":{
         "network": "grpc",
            "grpcSettings": {
                "serviceName": "vmess-grpc"
          }
        }
     },
     {
        "listen": "127.0.0.1",
        "port": "10007",
        "protocol": "trojan",
        "settings": {
          "decryption":"none",
             "clients": [
               {
                 "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
#trojangrpc
               }
           ]
        },
         "streamSettings":{
         "network": "grpc",
           "grpcSettings": {
               "serviceName": "trojan-grpc"
         }
      }
   },
   {
    "listen": "127.0.0.1",
    "port": "10008",
    "protocol": "shadowsocks",
    "settings": {
        "clients": [
          {
             "method": "aes-128-gcm",
             "password": "1d1c1d94-6987-4658-a4dc-8821a30fe7e0"
#ssgrpc 
           }
         ],
           "network": "tcp,udp"
      },
    "streamSettings":{
     "network": "grpc",
        "grpcSettings": {
           "serviceName": "ss-grpc"
          }
       }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "domainStrategy": "AsIs",
    "rules": [
      {
        "inboundTag": [
          "dnsIn"
        ],
        "outboundTag": "dnsOut",
        "type": "field"
      },
      {
        "inboundTag": [
          "dnsQuery"
        ],
        "outboundTag": "direct",
        "type": "field"
      },
      {
        "outboundTag": "direct",
        "protocol": [
          "bittorrent"
        ],
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "block",       
        "ip": [
          "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "::1/128", "fc00::/7", "fe80::/10"]
      },
      {
        "inboundTag": [
          "api"
        ],
        "outboundTag": "api",
        "type": "field"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      },
      {
        "type": "field",
        "outboundTag": "proxy",
        "ip": ["1.1.1.1/32", "1.0.0.1/32",
          "8.8.8.8/32", "8.8.4.4/32", "geoip:us", "geoip:ca", "geoip:cloudflare", "geoip:cloudfront", "geoip:facebook", "geoip:fastly", "geoip:google", "geoip:netflix", "geoip:telegram", "geoip:yt", "geoip:twitter"]
      },
      {
        "type": "field",
        "outboundTag": "block",       
        "ip": [
          "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "::1/128", "fc00::/7", "fe80::/10"]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "ip": ["223.5.5.5/32", "119.29.29.29/32", "180.76.76.76/32", "114.114.114.114/32", "geoip:cn", "geoip:jp", "geoip:in", "geoip:private"]
      },
      {
        "type": "field",
        "outboundTag": "reject",
        "domain": ["geosite:category-ads-all"]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "network": "tcp,udp"
      } 
    ]
  },
  "stats": {},
  "api": {
    "services": [
      "StatsService"
    ],
    "tag": "api"
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserDownlink": true,
        "statsUserUplink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true,
      "statsOutboundUplink" : true,
      "statsOutboundDownlink" : true
     }
    },
    "dns": {
      "hosts": {
        "dns.google": "8.8.8.8",
        "dns.pub": "119.29.29.29",
        "dns.alidns.com": "223.5.5.5",
        "geosite:category-ads-all": "127.0.0.1"
      },
      "servers": [
        {
          "address": "https://1.1.1.1/dns-query",
          "domains": ["geosite:geolocation-!cn"],
          "expectIPs": ["geoip:!cn"]
        },
        "8.8.8.8",
        {
          "address": "114.114.114.114",
          "port": 53,
          "domains": ["geosite:cn", "geosite:category-games@cn"],
          "expectIPs": ["geoip:cn"],
          "skipFallback": true
        },
        {
          "address": "localhost",
          "skipFallback": true
        }
       ]
      }
    }
END
rm -rf /etc/systemd/system/xray.service.d
cat <<EOF> /etc/systemd/system/xray.service
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE                                 AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target

EOF
cat > /etc/systemd/system/runn.service <<EOF
[Unit]
Description=Mampus-Anjeng
After=network.target

[Service]
Type=simple
ExecStartPre=-/usr/bin/mkdir -p /var/run/xray
ExecStart=/usr/bin/chown www-data:www-data /var/run/xray
Restart=on-abort

[Install]
WantedBy=multi-user.target
EOF

#nginx config
cat >/etc/nginx/conf.d/xray.conf <<EOF
server {
    listen 1010 proxy_protocol so_keepalive=on reuseport;
    set_real_ip_from 127.0.0.1;
    real_ip_header  proxy_protocol;
    server_name xxx;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-XSS-Protection "1; mode=block";

    location ~ /vless {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /vless break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10001;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /vmess {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /vmess break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10002;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  } 
    location ~ /trojan-ws {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /trojan-ws break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10003;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /ss-ws {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /ss-ws break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10004;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ / {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /sshws break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10015;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
server {
    listen 1012 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;

    location ~ / {
    if ($http_upgrade != "Websocket") {
    rewrite /(.*) /wsovpn break;
    }
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10012;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $http_x_forwarded_for;
    proxy_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
server {
    listen 81 ssl http2 reuseport;
    ssl_certificate /etc/xray/xray.crt;
    ssl_certificate_key /etc/xray/xray.key;
    ssl_ciphers EECDH+CHACHA20:EECDH+CHACHA20-draft:EECDH+ECDSA+AES128:EECDH+aRSA+AES128:RSA+AES128:EECDH+ECDSA+AES256:EECDH+aRSA+AES256:RSA+AES256:EECDH+ECDSA+3DES:EECDH+aRSA+3DES:RSA+3DES:!MD5;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    root /var/www/html;
}
server {
    listen 1013 http2 proxy_protocol so_keepalive=on reuseport;
    client_body_buffer_size 200K;
    client_header_buffer_size 2k;
    client_max_body_size 10M;
    large_client_header_buffers 3 1k;
    client_header_timeout 86400000m;
    keepalive_timeout 86400000m;
    server_name xxx;
    location ~ /vless-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10005;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /vmess-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10006;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /trojan-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10007;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
    location ~ /ss-grpc {
    add_header X-HTTP-LEVEL-HEADER 1;
    add_header X-ANOTHER-HTTP-LEVEL-HEADER 1;
    add_header X-SERVER-LEVEL-HEADER 1;
    add_header X-LOCATION-LEVEL-HEADER 1;
    proxy_headers_hash_max_size 512;
    proxy_headers_hash_bucket_size 128;
    proxy_http_version 1.1;
    proxy_redirect off;
    grpc_set_header Host $host;
    grpc_pass grpc://127.0.0.1:10008;
    grpc_set_header X-Real-IP $http_x_forwarded_for;
    grpc_set_header X-Forwarded-For $http_x_forwarded_for;
  }
}
sleep 1
echo -e "[ ${green}INFO$NC ] Installing bbr.."
wget -q -O /usr/bin/bbr "https://raw.githubusercontent.com/Paper890/sandi/main/ssh/bbr.sh"
chmod +x /usr/bin/bbr
bbr >/dev/null 2>&1
rm /usr/bin/bbr >/dev/null 2>&1
echo -e "$yell[SERVICE]$NC Restart All service"
systemctl daemon-reload
sleep 1
echo -e "[ ${green}ok${NC} ] Enable & restart xray "
systemctl enable xray
systemctl restart xray
systemctl restart nginx
systemctl enable runn
systemctl restart runn

sleep 1
wget -q -O /usr/bin/auto-set "https://raw.githubusercontent.com/Paper890/sandi/main/xray/auto-set.sh" && chmod +x /usr/bin/auto-set 
wget -q -O /usr/bin/crtxray "https://raw.githubusercontent.com/Paper890/sandi/main/xray/crt.sh" && chmod +x /usr/bin/crtxray 
sleep 1
yellow() { echo -e "\\033[33;1m${*}\\033[0m"; }
yellow "xray/Vmess"
yellow "xray/Vless"



mv /root/domain /etc/xray/ 
if [ -f /root/scdomain ];then
rm /root/scdomain > /dev/null 2>&1
fi
clear
rm -f ins-xray.sh  
