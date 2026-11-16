# zulip — pengarsip `.zynx`

Pengarsip clean-room dengan format sendiri (`.zynx`, format v5):
kompresi maksimum dari algoritma terbuka (Zstandard, LZMA2, Brotli),
enkripsi AES-256-GCM, recovery Reed-Solomon, multi-volume, SFX, dan
GUI Windows native dengan integrasi Explorer.

Prinsip utamanya: **ukuran arsip sekecil mungkin**. Mode Ultra (`-m5`)
mencoba semua kandidat codec + filter per blok dan menyimpan yang
terkecil — diverifikasi decode sebelum ditulis. Untuk pemakaian
sehari-hari ada mode Normal (`-m3`, bawaan klik kanan) yang secepat
ZIP dengan hasil jauh lebih kecil, dan mode Cepat (`-m1`).

> Catatan nama: "Zulip" juga merupakan nama produk team-chat
> open-source yang sudah dikenal. Nama proyek ini ditetapkan oleh
> pemiliknya; risiko kebingungan/trademark adalah pertimbangan nyata
> bila dipublikasikan secara luas.

## Unduh

Paket Windows siap pakai ada di halaman **Releases**: `zulip.exe`
(CLI), `zulip-gui.exe` (GUI), `zulip-stub.exe` (mesin SFX), dan
`install.bat` yang mendaftarkan asosiasi `.zynx` + menu klik kanan
Explorer (tanpa admin). Catatan: biner belum ditandatangani digital,
jadi SmartScreen menampilkan "More info → Run anyway" pada unduhan
pertama.

## Pakai (CLI)

```sh
zulip a -m5 backup.zynx folder/        # Ultra: terkecil
zulip a -m3 backup.zynx folder/        # Normal: cepat, tetap kecil
zulip a -m1 backup.zynx folder/        # Cepat
zulip a -m5 -p<password> rahasia.zynx folder/   # + enkripsi AES-256-GCM + Argon2id
zulip a -m5 -r10 backup.zynx folder/   # + recovery record Reed-Solomon 10%
zulip a -m5 -v10m backup.zynx folder/  # multi-volume: backup.zynx.001, .002, ...
zulip a -m5 --sfx paket folder/        # SFX: .exe yang mengekstrak dirinya
zulip l backup.zynx                    # daftar isi (ada --json)
zulip t backup.zynx                    # uji integritas SHA-256 (streaming)
zulip x backup.zynx tujuan/            # ekstrak aman + terverifikasi
zulip repair backup.zynx               # perbaiki kerusakan dari recovery record
zulip sfx backup.zynx                  # jadikan SFX untuk dibagikan
zulip tozip backup.zynx                # ekspor ke .zip universal
```

Berbagi ke orang yang tidak memasang zulip: buat **SFX** (penerima
klik dua kali, terekstrak tanpa instalasi — memakai stub pengekstrak
ramping 5,6 MB) atau ekspor ke **ZIP** yang dibuka semua OS.

## GUI Windows

`zulip-gui.exe` adalah jendela native (bukan wrapper web): daftar isi
arsip, dialog buat/ekstrak dengan semua opsi, bilah progres, dan
dialog Tentang. Setelah `install.bat` dijalankan:

- Klik ganda `.zynx` → membuka GUI
- Klik kanan `.zynx` → ekstrak di sini / dialog ekstrak / uji /
  buat SFX / konversi ZIP
- Klik kanan berkas/folder → "Kompres ke .zynx dengan zulip"
  (langsung, profil Normal), "opsi lanjut...", atau buat SFX

Di Windows 11, verb klasik muncul lewat "Show more options"
(kebijakan Microsoft, bukan batasan zulip).

## Cara kerja Ultra

1. Berkas dikelompokkan per kategori (binary PE disatukan) dan
   diproses sebagai grup solid per blok maksimum 32 MB.
2. Berkas identik dideduplikasi via SHA-256: disimpan sekali, entri
   lain hanya referensi.
3. Per blok, kandidat dievaluasi **paralel multi-core**: Zstd, Zstd +
   kamus terlatih, LZMA2, Brotli q11, masing-masing juga dengan
   filter pra-proses bila relevan — BCJ/BCJ2 (kode x86), Delta
   (data berstride seperti WAV/BMP), REP-lite (pengulangan jarak
   jauh). Yang terkecil menang; keluaran deterministik dan
   byte-identik dengan evaluasi sekuensial.
4. Index biner terkompresi di akhir arsip: list/test instan, dan
   pembacaan malas per blok (RAM sebatas blok, bukan arsip).
5. Penulisan atomik: arsip tidak pernah tertimpa parsial.

## Hasil terukur

Di VM pengembangan (CPU terbatas), corpus folder WinRAR 9,93 MB:

| Metode | Ukuran | Waktu |
|---|---|---|
| .zynx Ultra `-m5` | **32,9%** | 117 dtk |
| .zynx Normal `-m3` | 37,1% | 1,7 dtk |
| ZIP `-mx9` | 53,1% | 6,1 dtk |
| 7z `-mx9` | 29,9% | — |

Di laptop nyata (multi-core), folder 21,3 MB: Normal **1,80 dtk** dan
Ultra **17,30 dtk**, keduanya 25,3%. Corpus WAV PCM 6 MB: `.zynx`
68,0% **mengalahkan** 7z -mx9 (70,7%) berkat Brotli+Delta. Batas
jujurnya: berkas yang sudah terkompresi (video, zip, jpg) tidak bisa
menyusut berarti — itu batas entropi, bukan kelemahan alat.

## Keamanan

- Ekstraksi menolak path absolut, `..`, dan drive letter (pelajaran
  dari bug directory traversal WinRAR 7.12/7.13); symlink tidak
  disimpan.
- Setiap berkas diverifikasi SHA-256 saat ekstrak/test.
- Enkripsi: AES-256-GCM per blok + index, kunci dari Argon2id;
  nama berkas ikut tersembunyi; password salah atau data diubah
  = gagal total (tag GCM).
- Pembaca arsip difuzzing (192 ribu+ eksekusi bersih) dan diuji
  terhadap arsip rusak/terpotong: tidak pernah panic.

## Batas saat ini (jujur)

- Segmen recovery belum melindungi dirinya sendiri; recovery belum
  mendukung arsip multi-volume.
- REP-lite baru unggul pada grup >64–128 MB; di skala kecil window
  codec masih menutupinya.
- Biner Windows belum code-signed (SmartScreen, lihat di atas).
- Roadmap: paralelisasi antar-blok, kandidat PPMd untuk teks,
  recovery multi-volume.

## Build dari sumber

Butuh Go 1.22+:

```sh
go build -o zulip .              # CLI (Linux/macOS/Windows)
go build -o zulip-stub ./stub    # stub SFX
cd gui && GOOS=windows go build -ldflags "-H windowsgui" -o zulip-gui.exe .
```

Ikon, manifes, dan VERSIONINFO Windows tertanam lewat berkas
`resource_windows_*.syso` yang ikut ter-commit (dibangkitkan dengan
goversioninfo dari `versioninfo.json` + `gui/zulip.ico`).

Format arsip didokumentasikan di komentar `format.go`
(magic `ZYNX\x1a\x05`, blok solid 32 MB, index biner v5, footer
`ZYNX\x1aEND`). Reader tetap membaca `.zynx` v0.2–v0.4 dan `.adit`
v0.1. Sejarah desain lengkap: `ANALYSIS_AND_SPEC.md`.

## Lisensi

MIT — lihat `LICENSE`.
