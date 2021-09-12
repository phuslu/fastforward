#!/bin/bash

set -ex

cd "$(dirname "$0")"
PROJECT=liner
BUILDROOT=build

REVSION=r$(git rev-list --count HEAD)
LDFLAGS="-s -w -X main.version=${REVSION}"
SOURCES="README.md china.pac example.yaml liner.sh"

GOOS=${GOOS:-$(go env GOOS)}
GOARCH=${GOARCH:-$(go env GOARCH)}
CGO_ENABLED=${CGO_ENABLED:-$(go env CGO_ENABLED)}

if [ "${GOOS}" == "windows" ]; then
    SOURCES="README.md china.pac example.yaml liner-gui.exe"
    BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
    DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
    GOEXE=.exe
elif [ "${GOOS}" == "darwin" ]; then
    SOURCES="README.md china.pac example.yaml liner-gui.command"
    BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
    DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
elif [ "${GOARCH:0:3}" == "arm" ]; then
    if [ "$GOARCH" == "arm64" ]; then
        BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
        DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
    else
        BUILDDIR=${BUILDROOT}/${GOOS}_armv${GOARM}
        DISTFILE=${PROJECT}_${GOOS}_armv${GOARM}-${REVSION}
    fi
elif [ "${GOARCH:0:4}" == "mips" ]; then
    if [ "$GOMIPS" == "softfloat" ]; then
        BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}_${GOMIPS}
        DISTFILE=${PROJECT}_${GOOS}_${GOARCH}_${GOMIPS}-${REVSION}
    else
        BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
        DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
    fi
else
    BUILDDIR=${BUILDROOT}/${GOOS}_${GOARCH}
    DISTFILE=${PROJECT}_${GOOS}_${GOARCH}-${REVSION}
fi

build () {
    # go build
    mkdir -p ${BUILDDIR}
    env GOOS=${GOOS} \
        GOARCH=${GOARCH} \
        CGO_ENABLED=${CGO_ENABLED} \
    go build -v -trimpath -ldflags="${LDFLAGS}" -o ${BUILDDIR}/${PROJECT}${GOEXE} .
    # go test
    # go test -v .
    # cp files
    cp -r ${SOURCES} ${BUILDDIR}
    # changelog
    git log --oneline --pretty=format:"%h %s" -5 | tee ${BUILDDIR}/CHANGELOG
}

dist () {
    pushd ${BUILDDIR}
    env XZ_OPT=-9 tar cvJpf ../${DISTFILE}.tar.xz *
    popd
}

clean () {
    rm -rf ${BUILDDIR}
    rmdir ${BUILDROOT} || true
}

for a in $@; do $a; done
