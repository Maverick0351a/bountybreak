#!/bin/sh
set -eu

if [ "$#" -lt 6 ]; then
    echo "sandbox helper requires token, lab, entrypoint, timeout, CPU, and memory" >&2
    exit 2
fi

token=$1
lab=$2
entrypoint=$3
seconds=$4
cpu_seconds=$5
memory_bytes=$6
shift 6

case "$token" in *[!a-f0-9]*|'') echo "invalid token" >&2; exit 2;; esac
case "$entrypoint" in /*|*..*|*\\*) echo "invalid entrypoint" >&2; exit 2;; esac
case "$seconds:$cpu_seconds:$memory_bytes" in *[!0-9:]*|'') echo "invalid limits" >&2; exit 2;; esac

root="/tmp/scoperook-sandbox-$token"
cleanup() {
    umount -l "$root/proc" 2>/dev/null || true
    umount -l "$root/dev/urandom" 2>/dev/null || true
    umount -l "$root/dev/null" 2>/dev/null || true
    umount -l "$root/work" 2>/dev/null || true
    umount -l "$root/usr" 2>/dev/null || true
    umount -l "$root/etc/ld.so.cache" 2>/dev/null || true
    umount -l "$root" 2>/dev/null || true
    rm -rf "$root" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$root"
mount -t tmpfs -o nosuid,nodev,size=320m tmpfs "$root"
mkdir -p "$root/usr" "$root/etc" "$root/work" "$root/tmp" "$root/proc" "$root/dev"
chmod 1777 "$root/tmp"

mount --bind /usr "$root/usr"
mount -o remount,bind,ro "$root/usr"
if [ -f /etc/ld.so.cache ]; then
    : > "$root/etc/ld.so.cache"
    mount --bind /etc/ld.so.cache "$root/etc/ld.so.cache"
    mount -o remount,bind,ro "$root/etc/ld.so.cache"
fi
ln -s usr/bin "$root/bin"
ln -s usr/sbin "$root/sbin"
ln -s usr/lib "$root/lib"
if [ -d /usr/lib64 ]; then ln -s usr/lib64 "$root/lib64"; fi

mount --bind "$lab" "$root/work"
mount -o remount,bind,ro "$root/work"
: > "$root/dev/null"
: > "$root/dev/urandom"
mount --bind /dev/null "$root/dev/null"
mount --bind /dev/urandom "$root/dev/urandom"
mount -t proc -o nosuid,nodev,noexec proc "$root/proc"

set +e
chroot "$root" /usr/bin/setpriv \
    --reuid=65534 --regid=65534 --clear-groups --no-new-privs --bounding-set=-all \
    /usr/bin/env -i PATH=/usr/bin:/bin HOME=/tmp LANG=C.UTF-8 PYTHONHASHSEED=0 PYTHONNOUSERSITE=1 \
    /bin/sh -c '
        memory=$1; cpu=$2; seconds=$3; entry=$4; shift 4
        cd /work
        exec /usr/bin/prlimit --as="$memory" --cpu="$cpu" --fsize=65536 --nproc=32 --nofile=64 -- \
            /usr/bin/timeout --signal=KILL "${seconds}s" /usr/bin/python3 -I -B "$entry" "$@" \
            > /tmp/stdout.txt 2> /tmp/stderr.txt
    ' sandbox "$memory_bytes" "$cpu_seconds" "$seconds" "/work/$entrypoint" "$@"
exit_code=$?
set -e

printf 'SCOPEROOK_EXIT=%s\n' "$exit_code"
printf 'SCOPEROOK_STDOUT_B64='
/usr/bin/base64 -w0 "$root/tmp/stdout.txt" 2>/dev/null || true
printf '\nSCOPEROOK_STDERR_B64='
/usr/bin/base64 -w0 "$root/tmp/stderr.txt" 2>/dev/null || true
printf '\n'
