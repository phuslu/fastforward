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
checksum=$(curl -L https://github.com/phuslu/liner/releases/download/v0.0.0/checksums.txt | grep -E "liner_linux_${arch}-[0-9]+.tar.xz")
filename=$(echo $checksum | awk '{print $2}')
pacfile=$(head /dev/urandom | tr -dc '1-9' | head -c 6).pac

if test -d liner; then
  cd liner
elif test -x liner.sh; then
  true
else
  mkdir liner && cd liner
fi

curl -L https://github.com/phuslu/liner/releases/download/v0.0.0/$filename > $filename
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
          headers: "content-type: text/plain;charset=utf-8"
          file: $(pwd)/china.pac
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
Type=simple
KillMode=process
Restart=on-failure
WorkingDirectory=$(pwd)
EnvironmentFile=-$(pwd)/.env
ExecStart=$(pwd)/liner
StandardError=append:$(pwd)/liner.error.log
User=${USER}
Group=${USER}
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_SYS_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
EOF

echo ENV=production > .env

if hash systemctl; then
  rm -f liner.sh
  sudo systemctl enable $(pwd)/liner.service
  sudo systemctl restart liner
else
  rm -f liner.service
  sudo ./liner.sh restart
fi

echo "https://$domain/$pacfile"
