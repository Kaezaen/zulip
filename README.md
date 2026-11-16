<p align="center">
  <img src="gui/cat.png" width="128" alt="zulip logo">
</p>

<h1 align="center">zulip</h1>

<p align="center">
  A clean-room file archiver with its own <code>.zynx</code> format — built for one thing first: <strong>the smallest possible archive</strong>.<br>
  Best-of parallel compression (Zstd · LZMA2 · Brotli + BCJ2/Delta/REP-lite filters), AES-256-GCM encryption,<br>
  Reed–Solomon recovery, multi-volume sets, self-extracting packages, and a native Windows GUI.
</p>

<p align="center">
  <a href="https://github.com/Kaezaen/zulip/releases/tag/v0.8.0"><img src="https://img.shields.io/github/v/release/Kaezaen/zulip?label=release&color=black" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-black" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-black" alt="Platforms">
  <img src="https://img.shields.io/badge/written%20in-Go-black" alt="Written in Go">
</p>

---

## Why zulip?

Most archivers pick one codec and one trade-off. zulip's Ultra mode instead
**tries every serious candidate per block — in parallel — and keeps the
smallest verified result**: Zstd, Zstd with a trained dictionary, LZMA2, and
Brotli q11, each optionally preceded by the filter that fits the data (BCJ/BCJ2
for x86 binaries, Delta for strided data such as WAV/BMP, REP-lite for
long-range repetitions). Output is deterministic and byte-identical to a
sequential evaluation.

For everyday use, the Normal profile compresses a 21.3 MB folder in **1.8 s**
on a real laptop — ZIP-class speed at 25.3% of the original size, where ZIP
itself lands near 54%.

## Features

- **Three profiles** — `-m1` fast, `-m3` normal (default), `-m5` ultra (smallest)
- **Solid blocked format** — category-grouped solid blocks up to 32 MB, SHA-256
  deduplication of identical files, compressed binary index, lazy per-block reads
- **Encryption** — AES-256-GCM per block and index, Argon2id key derivation;
  file names are hidden, any tampering fails authentication
- **Recovery** — optional Reed–Solomon recovery record (`-r<pct>`) and a
  `repair` command that restores damaged blocks byte-identically
- **Multi-volume** — split archives (`-v<size>`) with per-volume headers and
  missing-volume detection
- **Sharing without zulip** — self-extracting `.exe` packages built on a lean
  5.6 MB stub, plus one-command export to universal ZIP
- **Safe by design** — extraction rejects absolute paths, `..`, and drive
  letters; every file is SHA-256-verified on extract/test; atomic writes
  (temporary file + rename) never leave a half-written archive
- **Native Windows GUI** — archive browser, create/extract dialogs, progress
  with ETA, and full Explorer integration (double-click to open, right-click
  to compress/extract/test/convert)
- **Backward compatible** — reads `.zynx` v0.2–v0.4 and `.adit` v0.1 archives

## Download

Get the Windows package from the
[**Releases**](https://github.com/Kaezaen/zulip/releases) page:
`zulip-0.8.0-windows.zip` contains `zulip.exe` (CLI), `zulip-gui.exe` (GUI),
`zulip-stub.exe` (SFX engine), and `install.bat`, which registers the `.zynx`
association and Explorer context menus under your user account — no admin
rights required.

> The binaries are not code-signed yet, so Windows SmartScreen will show
> "More info → Run anyway" on first launch. This is a certificate cost issue,
> not a code issue, and it is tracked openly here rather than hidden.

## Quick start

```sh
zulip a -m5 backup.zynx folder/          # Ultra — smallest archive
zulip a -m3 backup.zynx folder/          # Normal — fast, still small
zulip a -m1 backup.zynx folder/          # Fast
zulip a -m5 -p<password> secret.zynx folder/   # + AES-256-GCM encryption
zulip a -m5 -r10 backup.zynx folder/     # + 10% Reed–Solomon recovery record
zulip a -m5 -v10m backup.zynx folder/    # multi-volume: backup.zynx.001, .002, …
zulip a -m5 --sfx package folder/        # self-extracting .exe

zulip l backup.zynx                      # list contents (--json available)
zulip t backup.zynx                      # verify integrity (streaming, SHA-256)
zulip x backup.zynx dest/                # extract (safe + verified)
zulip repair backup.zynx                 # restore damage from recovery record
zulip sfx backup.zynx                    # wrap an archive as SFX for sharing
zulip tozip backup.zynx                  # export to universal .zip
```

On Windows, after running `install.bat`:

- **Double-click** a `.zynx` file to open it in the GUI
- **Right-click** a `.zynx` file → extract here, extract dialog, test,
  create SFX, or convert to ZIP
- **Right-click** any file/folder → "Kompres ke .zynx dengan zulip"
  (instant, Normal profile), advanced options, or create SFX

(On Windows 11 the classic verbs live under "Show more options" — a
Microsoft policy, not a zulip limitation.)

## Benchmarks

Measured, reproducible, and reported with the losses included.

Development VM (CPU-throttled), 9.93 MB WinRAR folder corpus:

| Method | Size | Time |
|---|---:|---:|
| zulip Ultra `-m5` | **32.9%** | 117 s |
| zulip Normal `-m3` | 37.1% | 1.7 s |
| ZIP `-mx9` | 53.1% | 6.1 s |
| 7z `-mx9` | 29.9% | — |

Real laptop (multi-core), 21.3 MB folder: Normal **1.80 s**, Ultra
**17.30 s**, both at 25.3%. On a 6 MB WAV PCM corpus, zulip reaches 68.0%
and **beats 7z -mx9** (70.7%) via Brotli+Delta.

The honest limit: already-compressed data (video, zip, jpeg) cannot shrink
meaningfully with any lossless archiver — that is an entropy bound, not a
tool defect.

## Security

- Extraction rejects absolute paths, `..` traversal, and drive letters —
  the class of bug behind WinRAR's CVE-2025 directory traversal issues.
  Symlinks are not stored.
- Every extracted or tested file is verified against its stored SHA-256.
- Encrypted archives authenticate every block and the index (GCM tags);
  a wrong password or a single flipped byte fails the whole operation.
- The archive reader is fuzz-tested (192k+ executions, zero panics) and
  exercised against truncated and randomly corrupted archives.

## Known limitations

- The recovery segment does not protect itself, and recovery does not yet
  cover multi-volume sets.
- REP-lite only wins on groups larger than ~64–128 MB; at smaller scales
  the codec windows already cover those repetitions.
- Windows binaries are unsigned (see Download note above).

## Building from source

Requires a recent Go toolchain (see `go.mod`).

```sh
go build -o zulip .                                   # CLI
go build -o zulip-stub ./stub                         # SFX stub
cd gui && GOOS=windows go build -ldflags "-H windowsgui" -o zulip-gui.exe .
go test ./...                                          # full test suite
```

Windows icon, manifest, and VERSIONINFO resources are committed as
`resource_windows_*.syso` files (generated with goversioninfo from
`versioninfo.json` and `gui/zulip.ico`). The stub keeps real copies of the
read-path sources so the repository clones and builds cleanly on Windows;
refresh them with `./sync-stub.sh` after changing the reader.

## Format

The `.zynx` format (v5) is documented in the comments of `format.go`:
magic `ZYNX\x1a\x05`, category-grouped solid blocks (max 32 MB), a
compressed binary index, and a `ZYNX\x1aEND` footer. The full design
history — every version, measurement, and trade-off — lives in
[`ANALYSIS_AND_SPEC.md`](ANALYSIS_AND_SPEC.md), with release notes in
[`CHANGELOG.md`](CHANGELOG.md).

## A note on the name

"Zulip" is also the name of a well-known open-source team chat product.
This project is unrelated to it; the name was a deliberate choice by the
author, and the potential for confusion is acknowledged here openly.

## License

[MIT](LICENSE) © 2026 Muhammad Aditya Pratama
