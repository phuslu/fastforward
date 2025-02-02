#!/bin/bash -xe

function setup() {
	export DEBIAN_FRONTEND=noninteractive
	apt update -y
	apt install -yq git curl jq zip bzip2 xz-utils

	git config --global --add safe.directory '*'

	mkdir -p ~/.ssh
	ssh-keyscan -H github.com | tee -a ~/.ssh/known_hosts

	curl -L https://github.com/phuslu/go/releases/download/v0.0.0/gotip.linux-amd64.tar.xz | \
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
	chmod -R +w ${golang_org_x_net}
	patch -p1 -d ${golang_org_x_net} <http2date.patch

	go build -v .
	go test -v .

	cat <<EOF |
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 ./make.bash build dist
CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 ./make.bash build dist
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 ./make.bash build dist
EOF
	xargs --max-procs=8 -n1 -i bash -c {}
}

function release() {
	pushd build

	sha1sum liner_* >checksums.txt
	git log --oneline --pretty=format:"%h %s" -5 | tee changelog.txt

	curl -L https://github.com/github-release/github-release/releases/download/v0.10.0/linux-amd64-github-release.bz2 | bzip2 -d >/usr/bin/github-release
	chmod +x /usr/bin/github-release

	github-release delete --user phuslu --repo liner --tag v0.0.0 || true
	cat changelog.txt | github-release release --user phuslu --repo liner --tag v0.0.0 --name v0.0.0 --description -
	sleep 5
	for file in liner_* checksums.txt changelog.txt; do
		github-release upload --replace --user phuslu --repo liner --tag v0.0.0 --name $file --file $file
	done

	popd
}


$1
