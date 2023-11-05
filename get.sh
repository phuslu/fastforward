#!/bin/bash

set -x

arch=amd64
case $(uname -m) in
  aarch64 )
    arch=arm64
    ;;
  arm* )
    arch=armv5
    if readelf -A /bin/sh | grep -q 'VFP registers'; then
      arch=armv7
    fi
    ;;
esac

domain=$(curl -sS whatismyip.akamai.com | tr . -).nip.io
checksum=$(curl https://phus.lu/liner/checksums.txt | grep -E "liner_linux_${arch}-[0-9]+.tar.xz")
filename=$(echo $checksum | awk '{print $2}')
pacfile=$(shuf -er -n6 1 2 3 4 5 6 7 8 9 | tr -d '\n').pac

if test -d liner; then
  cd liner
elif test -x liner.sh; then
  true
else
  mkdir liner && cd liner
fi

curl http://phus.lu/liner/$filename > $filename
if test "$(sha1sum $filename)" != "$checksum"; then
  echo "$filename sha1sum mismatched, please check your network!"
  rm -rf $filename
  exit 1
fi

tar xvJf $filename
rm -rf $filename

if test -f production.yaml; then
  exit 0
fi

cat <<EOF > production.yaml
global:
  log_level: info
  max_idle_conns: 100
  dial_timeout: 30
  dns_cache_duration: 15m
https:
  - listen: [':443']
    server_name: ['$domain']
    forward:
      log: true
      prefer_ipv6: false
      policy: |
        {{if all (.Request.ProtoAtLeast 2 0) (eq .Request.TLS.Version 0x0304) (greased .ClientHelloInfo)}}
            bypass_auth
        {{else}}
            proxy_pass
        {{end}}
    web:
      - location: /$pacfile
        index:
          file: $(pwd)/$pacfile
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
WorkingDirectory=$(pwd)
ExecStart=$(pwd)/liner.sh start
ExecStop=$(pwd)/liner.sh stop
ExecReload=$(pwd)/liner.sh reload

[Install]
WantedBy=multi-user.target
EOF

echo ENV=production > .env
mv china.pac $pacfile

sudo ./liner.sh restart
hash systemctl 2>/dev/null && sudo systemctl enable $(pwd)/liner.service

echo "https://$domain/$pacfile"
