#!/bin/bash

set -x

echo >/dev/tcp/127.0.0.1/80 || (
	if hash yum; then
		sudo yum install -y epel-release
		sudo yum install -y nginx
		sudo chkconfig nginx on
		sudo service nginx start
	elif hash apt-get; then
		sudo apt-get install -y nginx
		sudo update-rc.d nginx defaults
		sudo service nginx start
	else
		echo please install nginx
	fi
)

ip=$(curl whatismyip.akamai.com)
domain=$(echo $ip | tr . -).nip.io
filename=$(curl https://liner.ml | egrep -o 'liner_linux_amd64-r....tar.gz'  | head -1)
pacfile=$(head -c 6 /dev/urandom | base64 | tr -d =/+).pac

if test -d liner; then
	cd liner
elif test -x liner.sh; then
	true
else
	mkdir liner && cd liner
fi

curl https://liner.ml/$filename | tar xvz

if test -f production.toml; then
	exit 0
fi

cat <<EOF > production.toml
[log]
level = 'info'
backups = 2
maxsize = 1073741824
localtime = true

[global]
max_idle_conns = 100
dial_timeout = 30
dns_ttl = 1800
prefer_ipv6 = false
dns_server = 'https://1.1.1.1/dns-query'

[upstream]
torsocks = {scheme='socks5h', host='127.0.0.1', port=9050}

[[https]]
listen = [':443', ':8443']
server_name = ['$domain']
forward_policy = '''
    {{if all (.Request.ProtoAtLeast 2 0) (eq .Request.TLS.Version 0x0304) (greased .ClientHelloInfo)}}
        bypass_auth
    {{else}}
        proxy_pass
    {{end}}
'''
forward_upstream = '{{if hasSuffix ".onion" .Request.Host}}torsocks{{end}}'
forward_log = true
pac_enabled = true
pac_iplist = 'https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt'
proxy_pass = 'http://127.0.0.1:80'
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
mv proxy.pac $pacfile

sudo ./liner.sh restart
hash systemctl 2>/dev/null && sudo systemctl enable $(pwd)/liner.service

echo "https://$domain/$pacfile"