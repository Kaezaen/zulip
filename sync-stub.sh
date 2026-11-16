#!/bin/sh
# Segarkan salinan berkas jalur-baca di stub/ dari paket utama.
# stub/ memakai SALINAN (bukan symlink) agar repo bisa di-clone dan
# dibangun di Windows tanpa dukungan symlink.
set -e
cd "$(dirname "$0")"
for f in blockreader.go codec.go crypto.go filters.go format.go read.go recovery.go sfx.go source.go streamfilters.go ui.go volume.go; do
  [ -f "$f" ] && cp "$f" "stub/$f"
done
echo "stub/ tersegar dari paket utama."
