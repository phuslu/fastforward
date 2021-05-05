#!/bin/bash

set -x

arch=amd64
case $(uname -m) in
  arm* )
    arch=armv5
    if readelf -A /bin/sh | grep -q 'VFP registers'; then
      arch=armv7
    fi
    ;;
esac

ip=$(curl whatismyip.akamai.com)
domain=$(echo $ip | tr . -).nip.io
filename=$(curl golab.cc | egrep -o "liner_linux_${arch}-r[0-9]+.tar.xz"  | head -1)
pacfile=$(head -c 6 /dev/urandom | base64 | tr -d =/+).pac

if test -d liner; then
	cd liner
elif test -x liner.sh; then
	true
else
	mkdir liner && cd liner
fi

curl golab.cc/$filename | tar xvJ

if test -f production.yaml; then
	exit 0
fi

cat <<EOF > production.yaml
log:
  level: info
  backups: 2
  maxsize: 1073741824
  localtime: true
global:
  max_idle_conns: 100
  dial_timeout: 30
  dns_ttl: 1800
  prefer_ipv6: false
upstream:
  torsocks:
    scheme: socks5h
    host: 127.0.0.1
    port: 9050
https:
  - listen: [':443', ':8443']
    server_name: ['$domain']
    forward:
      policy: |
        {{if all (.Request.ProtoAtLeast 2 0) (eq .Request.TLS.Version 0x0304) (greased .ClientHelloInfo)}}
            bypass_auth
        {{else}}
            proxy_pass
        {{end}}
      upstream: |
        {{if hasSuffix ".onion" .Request.Host}}torsocks{{end}}
      log: true
    web:
      - location: /*.pac
        pac:
          enabled: true
      - location: /
        proxy:
          pass: 'http://127.0.0.1:80'
EOF

cat <<EOF > liner.service
[Unit]
Wants=network-online.target
After=network.target network-online.target
Description=liner

[Service]
Type=forking
KillMode=process
AmbientCapabilities=CAP_NET_BIND_SERVICE
User=$(whoami)
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/liner.sh start
ExecStop=$(pwd)/liner.sh stop
ExecReload=$(pwd)/liner.sh reload

[Install]
WantedBy=multi-user.target
EOF

echo ENV=production | tee .env
mv china.pac $pacfile

sudo ./liner.sh restart
hash systemctl 2>/dev/null && sudo systemctl enable $(pwd)/liner.service

echo "https://$domain/$pacfile"
