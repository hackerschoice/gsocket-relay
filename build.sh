#!/usr/bin/env bash
set -euo pipefail

usage() {
    printf 'Usage: %s [source-directory]\n' "$0"
    printf 'Build static x86_64 Linux binaries from tracked working-tree files, including uncommitted edits.\n'
    printf 'Requires Docker, Git, and tar. The default source directory contains this script.\n'
    printf 'OUTPUT_DIR overrides the destination (default: ${XDG_CACHE_HOME:-$HOME/.cache}/gsocket-relay/musl-x86_64).\n'
}

if [[ ${1:-} == -h || ${1:-} == --help ]]; then
    usage
    exit 0
fi
if (( $# > 1 )); then
    usage >&2
    exit 1
fi
for dependency in docker git tar; do
    command -v "$dependency" >/dev/null || { printf 'Required command not found: %s\n' "$dependency" >&2; exit 1; }
done

PROJECT_DIR=$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")}" && pwd -P)
if [[ $(git -C "$PROJECT_DIR" rev-parse --show-toplevel) != "$PROJECT_DIR" ]]; then
    printf 'Source directory must be the Git repository root: %s\n' "$PROJECT_DIR" >&2
    exit 1
fi
OUTPUT_DIR=${OUTPUT_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/gsocket-relay/musl-x86_64}
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(cd "$OUTPUT_DIR" && pwd -P)
BUILD_DIR=$(mktemp -d "${TMPDIR:-/tmp}/gsocket-relay-build.XXXXXX")
BUILD_DIR=$(cd "$BUILD_DIR" && pwd -P)
trap 'rm -rf -- "$BUILD_DIR"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$BUILD_DIR/source"
git -C "$PROJECT_DIR" ls-files -z > "$BUILD_DIR/source-files"
tar -C "$PROJECT_DIR" -cf - --null -T "$BUILD_DIR/source-files" | tar -C "$BUILD_DIR/source" -xf -

IMAGE=gsocket-relay-musl-x86_64:openssl-1.1.1w-libevent-2.1.12
docker build --platform linux/amd64 --tag "$IMAGE" - <<'DOCKERFILE'
FROM muslcc/x86_64@sha256:173c042a23a544defa3364d4472b30b36af1d827a74cd8dab7683b8500004334
RUN apk add --update --no-cache --no-progress tar git autoconf automake make curl bsd-compat-headers file bash perl pkgconf python3
WORKDIR /tmp
RUN curl --fail --show-error --location --retry 3 https://www.openssl.org/source/openssl-1.1.1w.tar.gz -o openssl.tar.gz && sha256sum openssl.tar.gz > /opt/dependency-sha256.txt && tar -xzf openssl.tar.gz && cd openssl-1.1.1w && ./Configure --prefix=/opt no-tests no-dso no-threads no-shared linux-generic64 && make -j4 && make install_sw
RUN curl --fail --show-error --location --retry 3 https://github.com/libevent/libevent/releases/download/release-2.1.12-stable/libevent-2.1.12-stable.tar.gz -o libevent.tar.gz && sha256sum libevent.tar.gz >> /opt/dependency-sha256.txt && tar -xzf libevent.tar.gz && cd libevent-2.1.12-stable && PKG_CONFIG_PATH=/opt/lib/pkgconfig CFLAGS="-I/opt/include" LDFLAGS="-L/opt/lib" ./configure --prefix=/opt --enable-static --host=x86_64 && make -j4 install
RUN rm -rf /tmp/openssl-1.1.1w /tmp/libevent-2.1.12-stable /tmp/openssl.tar.gz /tmp/libevent.tar.gz /opt/bin/openssl /opt/bin/c_rehash
WORKDIR /work
DOCKERFILE

docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" --mount "type=bind,source=$BUILD_DIR,target=/work" --mount "type=bind,source=$OUTPUT_DIR,target=/output" -i "$IMAGE" sh -s <<'BUILD'
set -eu
revision=c58818d15b4294b54adcc9992b9f699ecc201ad7
curl --fail --show-error --location --retry 3 "https://codeload.github.com/hackerschoice/gsocket/tar.gz/$revision" -o gsocket.tar.gz
printf '%s\n' '2b059e2387e998dfaa4323643c9b5d69c6b205abe3739fef9091c4f783c0bee4  gsocket.tar.gz' | sha256sum -c -
mkdir source/gsocket
tar -xzf gsocket.tar.gz --strip-components=1 -C source/gsocket
cd source/gsocket
./bootstrap
./configure --prefix=/opt --enable-realprefix=/usr --enable-static --host=x86_64
make -j4 all
cd /work/source
./bootstrap
LDFLAGS="-L/opt/lib" LIBS="-lssl -lcrypto" ./configure --prefix=/opt --enable-static --host=x86_64
make -j4
file src/gsrnd src/gsrn_cli
cp src/gsrnd /output/gsrnd-linux-x86_64
cp src/gsrn_cli /output/gsrn_cli-linux-x86_64
BUILD

printf '\nBinaries written to %s\n' "$OUTPUT_DIR"
