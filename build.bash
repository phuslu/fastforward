#!/bin/bash -xe

function setup() {
	sudo DEBIAN_FRONTEND=noninteractive apt install -yq sshpass rsync git curl zip jq

	mkdir -p ~/.ssh
	ssh-keyscan -H github.com | tee -a ~/.ssh/known_hosts

	curl -s https://golang.org/dl/ |
	grep -oP -m1 'https://dl.google.com/go/go[0-9.]+.linux-amd64.tar.gz' |
	xargs curl |
	tar xz -C /tmp/
}

function build() {
	export CGO_ENABLED=0
	export GOROOT=/tmp/go
	export GOPATH=/tmp/gopath
	export PATH=${GOPATH}/bin:${GOROOT}/bin:$PATH

	if grep -lr $(printf '\r\n') * | grep '.go$' ; then
		echo -e "\e[1;31mPlease run dos2unix for go source files\e[0m"
		exit 1
	fi

	if [ "$(gofmt -l .)" != "" ]; then
		echo -e "\e[1;31mPlease run 'gofmt -s -w .' for go source files\e[0m"
		exit 1
	fi

	go version
	go env

	#go list -deps | egrep '^[^/]+\.[^/]+/' | xargs -n1 -i go get -u -v {}

	go build -v .
	go test -v .

	cat <<EOF |
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 ./make.bash build dist
CGO_ENABLED=0 GOOS=darwin GOARCH=arm GOARM=7 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 ./make.bash build dist
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 ./make.bash build dist
CGO_ENABLED=0 GOOS=windows GOARCH=arm GOARM=7 ./make.bash build dist
EOF
	xargs --max-procs=8 -n1 -i bash -c {}
}

function packaging_macos() {
	pushd build

	local revison=r$(git rev-list --count HEAD)

	mkdir -p liner
	tar xvpf liner_darwin_amd64-${revison}.tar.gz -C liner
	cat <<EOF > liner/production.toml
[log]
level = 'debug'

[global]
max_idle_conns = 16
dial_timeout = 30
dns_ttl = 900
prefer_ipv6 = false

[upstream]
https_hk = {scheme='https', username='leader.one', password='123456', host='flyspace.hk', port=443}

[[http]]
listen = ['127.0.0.1:8087']
server_name = ['localhost', '127.0.0.1']
forward_policy = 'bypass_auth'
forward_upstream = 'https_hk'
pac_enabled = true
pac_iplist = 'https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt'
EOF
	# clean old files
	rm liner_darwin_amd64-${revison}.tar.gz
	GZIP_OPT=-9 tar cvzpf liner_macos_amd64-${revison}.tar.gz liner
	rm -rf liner

	popd
}

function packaging_windows() {
	pushd build

	local revison=r$(git rev-list --count HEAD)
	for arch in amd64 arm; do
		mkdir -p liner
		tar xvpf liner_windows_${arch}-${revison}.tar.gz -C liner
		cat <<EOF > liner/production.toml
[log]
level = 'debug'

[global]
max_idle_conns = 16
dial_timeout = 30
dns_ttl = 900
prefer_ipv6 = false

[upstream]
https_hk = {scheme='https', username='leader.one', password='123456', host='flyspace.hk', port=443}

[[http]]
listen = ['127.0.0.1:8087']
server_name = ['localhost', '127.0.0.1']
forward_policy = 'bypass_auth'
forward_upstream = 'https_hk'
pac_enabled = true
pac_iplist = 'https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt'
EOF
		# clean old files
		rm liner_windows_${arch}-${revison}.tar.gz
		zip -9 -r liner_windows_${arch}-${revison}.zip liner
		rm -rf liner
	done

	popd
}

function release() {
	pushd build

	ssh-keyscan -H liner.website | tee -a ~/.ssh/known_hosts
	sshpass -p "${SSH_PASSWORD}" ssh phuslu@liner.website 'rm -rf /var/www/liner/liner_*'
	sshpass -p "${SSH_PASSWORD}" rsync --progress -avz liner_* "phuslu@liner.website:/var/www/liner/"

	popd
}


$1
