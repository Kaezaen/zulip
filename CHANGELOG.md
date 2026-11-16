# Catatan Rilis zulip

## 0.8.0 — 2026-11-15
- Kecepatan: klik kanan "Kompres ke .zynx" kini memakai profil Normal
  (data terukur: ~1,7 dtk vs 117 dtk Ultra pada folder WinRAR 10 MB,
  tetap jauh lebih kecil dari ZIP). Kandidat Ultra dievaluasi paralel
  multi-core dengan keluaran byte-identik.
- GUI didesain ulang: pita header berlogo, bar status, dialog berikon,
  dialog Tentang berlogo, penjaga crash dengan log diagnostik.
- Metadata versi Windows (VERSIONINFO) di semua .exe.
- LICENSE (MIT) dan CHANGELOG ditambahkan.

## 0.7.2 — 2026-11-15
- Berbagi ke non-pengguna: `zulip sfx` + stub pengekstrak ramping
  5,6 MB, `zulip tozip`, verb klik kanan SFX/ZIP.
- Perbaikan bug sharing violation saat membuat SFX di Windows.

## 0.7.1 — 2026-11-15
- Perbaikan bug nilai dialog kosong (snapshot sebelum dialog tutup).
- Klik kanan langsung: --quickadd, --extracthere, --test.
- Logo kucing hitam + bel emas.

## 0.7.0 — 2026-11-15
- GUI Windows native + integrasi Explorer (asosiasi .zynx, menu konteks).
- CLI: mode daftar JSON.

## 0.6.0 — 2026-11-15
- UI/UX CLI: progres ber-ETA, kartu ringkasan, tabel daftar, petunjuk error.

## 0.5.0 — 2026-11-15
- Hardening: format v5 berblok 32 MB, tulis streaming + atomik, fuzzing bersih.

## 0.4.0 — 2026-11-15
- Index biner v4, multi-volume, recovery Reed-Solomon, SFX.

## 0.3.0 — 2026-11-15
- Filter Delta/BCJ2/REP-lite, enkripsi AES-256-GCM + Argon2id.

## 0.2.0 — 2026-11-15
- Format .zynx v2: index biner, Brotli q11 + BCJ, streaming ekstrak.

## 0.1.0 — 2026-11-15
- Rilis awal (sebagai .adit): solid grouping, dedup SHA-256, best-of codec.
