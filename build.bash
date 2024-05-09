#!/bin/bash -xe

function setup() {
	sudo DEBIAN_FRONTEND=noninteractive apt install -yq sshpass rsync git curl zip jq

	mkdir -p ~/.ssh
	ssh-keyscan -H github.com | tee -a ~/.ssh/known_hosts

	curl -L https://github.com/phuslu/go/releases/download/v0.0.0/go1.22.linux-amd64.tar.xz | \
	tar xvJ -C /tmp/
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

	# if [ "$(gofmt -l .)" != "" ]; then
	# 	echo -e "\e[1;31mPlease run 'gofmt -s -w .' for go source files\e[0m"
	# 	exit 1
	# fi

	go version
	go env

	go mod download -x
	golang_org_x_net="${GOPATH}/pkg/mod/$(go list -m golang.org/x/net | tr ' ' @)"
	chmod +w ${golang_org_x_net}/http2 ${golang_org_x_net}/http2/server.go
	patch -p1 -d ${golang_org_x_net} <02-http2date.patch

	go build -v .
	go test -v .

	cat <<EOF |
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 ./make.bash build dist
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 ./make.bash build dist
EOF
	xargs --max-procs=8 -n1 -i bash -c {}
}

function release() {
	pushd build

	sha1sum liner_* >checksums.txt

	local ssh_host=phus.lu
	ssh-keyscan -H ${ssh_host} | tee -a ~/.ssh/known_hosts
	sshpass -p "${SSH_PASSWORD}" ssh phuslu@${ssh_host} 'rm -rf /home/phuslu/web/liner/liner_*'
	sshpass -p "${SSH_PASSWORD}" rsync --progress -avz liner_* checksums.txt "phuslu@${ssh_host}:/home/phuslu/web/liner/"

	popd
}


$1
