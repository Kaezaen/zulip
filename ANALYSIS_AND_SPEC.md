# Analisa WinRAR.zip + Spesifikasi Versi Kita

Tanggal analisa: 15 Nov 2026
File sumber: workspace/user/files/WinRAR.zip
SHA-256: 3cfcfe170d00f070abae4c2d29c7abf803ea453ded7fc35a96a9d44f8b52f8f4
Ukuran zip: 5.448.015 byte | Isi: 31 file, 9.933.280 byte (uncompressed)

## 1. Ini file apa sebenarnya

BUKAN source code. Ini folder instalasi WinRAR yang di-zip (compression: store di level zip luar).
Versi terverifikasi dari PE version resource semua binary utama:

- Product: WinRAR 7.13.0 (x64, plus modul 32-bit untuk SFX/shell)
- Company: Alexander Roshal, Copyright 1993-2025, diterbitkan win.rar GmbH, Berlin
- Lisensi: proprietary, trial 40 hari ("try before you buy"), lihat License.txt poin 2-3.
  Dilarang mendistribusikan bagian paket secara terpisah kecuali komponen UnRAR.
  Konsekuensi: kita TIDAK boleh menyalin kode/algoritma RAR. Wajib clean-room:
  format sendiri, algoritma terbuka, nama + ekstensi sendiri.

## 2. Peta komponen (31 file)

| Komponen | Ukuran | Fungsi |
|---|---|---|
| WinRAR.exe | 3.412.688 | GUI utama (PE32+ x86-64, 8 section) |
| Rar.exe | 835.792 | CLI full: create + extract (console) |
| UnRAR.exe | 561.872 | CLI extract-only, freeware — satu-satunya yang boleh disebar bebas |
| Default.SFX / Default32.SFX | 482.304 / 387.072 | Stub self-extracting GUI RAR (64/32-bit) |
| WinCon.SFX / WinCon32.SFX | 424.448 / 342.016 | Stub SFX console RAR |
| Zip.SFX / Zip32.SFX | 494.080 / 349.184 | Stub SFX untuk ZIP |
| RarExt.dll / RarExt32.dll | 667.856 / 555.728 | Shell extension Explorer (context menu, drag-drop) |
| RarExtInstaller.exe + RarExtPackage.msix + Resources.pri + logo PNG | - | Registrasi shell extension modern (MSIX) |
| 7zxa.dll | 228.048 | HANYA dekompresi 7z — bukan encoder 7z |
| WinRAR.chm, Rar.txt (111.927), WhatsNew.txt (57.844) | - | Help + manual CLI lengkap |
| rarnew.dat | 24 byte | Template arsip RAR5 kosong (lihat seksi 3) |
| zipnew.dat | 22 byte | Template ZIP kosong: PK\x05\x06 + 18 byte nol (End Of Central Directory) |
| Uninstall.exe/.lst, License.txt, Order.htm, Descript.ion, RarFiles.lst | - | Uninstaller, lisensi, deskripsi, urutan sort solid |

## 3. Format RAR5 — dibedah dari rarnew.dat (24 byte)

```
Offset 0:  52 61 72 21 1A 07 01 00   Signature "Rar!\x1a\x07\x01\x00" (8 byte, RAR5)
Offset 8:  Block 1 — Main header: CRC32 header (4 byte) + varint header_size + varint type=1 + varint flags
Offset ..: Block 2 — Service header (Quick Open Information)
Format umum tiap block: [Header CRC32][varint HeaderSize][varint Type][varint Flags][varint ExtraSize?][varint DataSize?]...[data]
Tipe block: 1=Main, 2=File, 3=Service, 4=Encryption, 5=End of archive
Panjang integer = variable-length (varint, 7-bit per byte) — bukan fixed size.
```

Pelajaran desain: signature pendek + block berantai + varint = format extensible,
tapi listing file harus scan dari depan (lambat untuk arsip besar) — RAR mengakalinya
dengan service block "Quick Open Information". Versi kita perbaiki ini (lihat seksi 6).

## 4. Fitur inti WinRAR 7.13 (dari ReadMe + Rar.txt + WhatsNew)

Buat (create): HANYA RAR dan ZIP. Buka (unpack): RAR, ZIP, 7Z, ARJ, BZ2, CAB, GZ, ISO,
JAR, LZ, LZH, TAR, UUE, XZ, Z, ZST.

- Kompresi proprietary: metode -m0 store, -m1 fastest .. -m5 best (default -m3).
  Dictionary sliding 128 KB - 4 GB (RAR5), diperluas sampai 64 GB (RAR 7.x), default 32 MB.
  Long-range search untuk -m2..-m5.
- Solid archive: semua file diperlakukan satu stream — rasio naik 10-50% untuk banyak
  file kecil. Urutan file di-sort per ekstensi (RarFiles.lst: .txt/.doc dulu, media terkompresi terakhir).
  Trade-off: ekstrak 1 file lambat, kerusakan 1 titik merusak lanjutan stream.
- Enkripsi: AES-256 (RAR5), opsi enkripsi header/nama file (-hp), password >127 karakter didukung.
  Checksum file pilihan: CRC32 (-htc) atau BLAKE2sp 256-bit (-htb).
- Recovery: recovery record Reed-Solomon (-rr, sampai 1000% ukuran data di RAR5),
  recovery volumes .rev (-rv), perintah repair `r` dua tahap, reconstruct volume `rc`.
- Multi-volume: split ke part dengan ukuran bebas (-v), bisa SFX multi-volume.
- SFX: stub .SFX ditempel di depan arsip -> .exe yang ekstrak sendiri, scriptable
  (TempMode, Silent, TextDone, dll).
- CLI: ~20 command (a,c,ch,cw,d,e,f,k,l,m,p,r,rc,rn,rr,rv,s,t,u,v,x) + 100+ switch.
  Ini permukaan fitur sebenarnya — GUI hanya membungkus CLI ini.
- Lainnya: archive comment maks 256 KB, lock archive (k), timestamp presisi tinggi
  (nanosecond Unix dipertahankan sejak 7.12), NTFS security/streams, symlink handling,
  file reference/deduplikasi, quick open information.

## 5. Pelajaran keamanan — dari WhatsNew 7.12 & 7.13 (jangan ulangi)

1. Directory traversal SAAT EKSTRAKSI diperbaiki DUA versi berturut-turut (7.12 dan 7.13,
   dilaporkan ESET + Trend Micro ZDI): arsip jahat bisa memaksa path di luar folder tujuan.
   -> Di versi kita: ekstraksi aman adalah fitur inti v1, bukan patch. Tolak absolut path,
      `..`, drive letter, dan symlink yang keluar dari destination. Default -ola ala RAR tidak ada.
2. HTML injection di "Generate report": nama file disisipkan mentah ke HTML.
   -> Escape semua nama file di output/log/report apa pun.
3. Symlink ke executable mengabaikan Mark-of-the-Web (7.11).
   -> Perlakukan symlink/hardlink sebagai data tidak tepercaya secara default.

## 6. Versi kita — spesifikasi draf v1

### Identitas (MENUNGGU PILIHAN COMMANDER)
- Nama kerja: AditArchiver / `adit` (CLI)
- Ekstensi kandidat utama: `.adit` — 4 huruf seperti .rar/.zip, personal, belum dipakai format arsip besar.
  Alternatif: `.adta`, `.ditya`, `.mpr` (catatan: .ptm/.adp sudah terpakai format lain, hindari).

### Format `.adit` v1 (clean-room, terinspirasi konsep — bukan turunan RAR)
```
[Magic 8 byte: "ADIT\x1a\x01\x00\x00"]
[Main Header block]
[File Header + Data block] x N      <- per-file (non-solid default)
[Optional Solid block]              <- v2
[Optional Recovery block: Reed-Solomon parity]  <- v3
[Central Index di AKHIR file]       <- keunggulan vs RAR: list/test instan tanpa scan, pola ZIP-central-directory + quick-open RAR digabung
[End Header: offset index + BLAKE2b/SHA-256 seluruh arsip + comment]
```
- Semua integer varint (LEB128), semua header punya CRC sendiri, nama file UTF-8 selalu.
- Kompresi TERBUKA: store (0), Zstandard (default, rasio+kecepatan terbaik, open-source),
  LZMA2/XZ (maksimum), Deflate (kompatibilitas). Tidak ada algoritma proprietary.
- Enkripsi TERBUKA + authenticated: XChaCha20-Poly1305 atau AES-256-GCM,
  KDF Argon2id (fallback PBKDF2-HMAC-SHA256). Enkripsi header = opsi, AEAD membuat
  tamper langsung terdeteksi — lebih kuat dari skema RAR5 (AES-CBC + checksum terpisah).
- Integritas: SHA-256 / BLAKE2b-256 per file + per block.
- Ekstraksi aman by-design (seksi 5), batas anti zip-bomb (rasio + total size quota).

### Roadmap
- MVP (v0.1): CLI `adit a|x|l|t|d` — create/list/extract/test/delete, store+zstd,
  per-file, timestamp + permission Unix/Windows dasar, ekstraksi aman. Bahasa: Go
  (stack utama Commander, single binary statis = padanan Rar.exe, cross-platform).
  Catatan: Go belum terinstal di VM ini — perlu install saat mulai coding.
- v0.2: solid mode, split volumes, password (AEAD + Argon2id), archive comment, quick list dari central index.
- v0.3: recovery record Reed-Solomon + repair, SFX stub (tempel stub ke arsip), GUI sederhana / shell integration.

### Yang SENGAJA tidak ditiru
- Algoritma kompresi RAR & format .rar (proprietary, lisensi).
- Kompatibilitas baca/tulis .rar — versi kita hanya membaca .zip/.tar/.gz umum bila nanti dibutuhkan.
- Trial nag-screen / registrasi — versi kita open / bebas.

## 7. Keputusan yang dibutuhkan untuk mulai bangun
1. Nama + ekstensi final: `.adit` atau kandidat lain?
2. Bahasa: Go (rekomendasi) — atau Python untuk prototipe format tercepat dulu?
3. Scope rilis pertama: MVP CLI saja (rekomendasi) atau langsung + enkripsi?

---

## 8. REVISI PRIORITAS (15 Nov 2026) — ULTRA COMPRESSION = FITUR UTAMA

Perintah Commander: fitur yang dibutuhkan adalah kompresi tingkat tinggi yang
overpower, hasil akhir sekecil mungkin. Kecepatan kompresi BUKAN prioritas.
Ekstrak tetap harus cepat.

### Pipeline `-m5 ultra` (wajib, berurutan)
1. ANALYZE — deteksi tipe dari magic bytes, bukan ekstensi. File entropi tinggi
   (jpg/mp4/zip/terenkripsi) -> store, jangan bakar CPU percuma.
2. DEDUP file-level — isi identik (hash BLAKE2b/SHA-256) disimpan sekali,
   entri lain hanya referensi. Duplikat = hemat 100%.
3. GROUPING + SORTING solid — file sejenis dikelompokkan berurutan supaya pola
   berulang jatuh dalam satu window dictionary (evolusi RarFiles.lst RAR).
4. DICTIONARY TRAINING — untuk banyak file kecil sejenis, latih dictionary Zstd
   (COVER) dari sampel arsip itu sendiri, simpan dict 8-112 KB di header.
   Target: kasus terburuk semua archiver umum = file kecil.
5. SOLID STREAM + LONG-RANGE — satu stream per grup, window 256 MB-1 GB,
   long-range matcher aktif.
6. ENGINE best-of per grup — Zstd level 22 ultra + long-range DAN LZMA2 -9e
   dicoba, yang lebih kecil disimpan (flag pemenang di header grup).
   Executable dilewatkan filter BCJ x86 dulu, data numerik/tabular delta filter.
7. DEDUP chunk-level (v2) — FastCDC untuk file besar mirip-tapi-tidak-identik
   (backup, image VM, dataset berversi).
8. VERIFY — decode + cek hash internal sebelum arsip dinyatakan selesai.

### Mode kompresi
- `-m1 fast`   : Zstd -3, per-file
- `-m3 normal` : Zstd -19, per-file + dedup file-level
- `-m5 ultra`  : pipeline penuh di atas (flagship)

### Batas fisika (jujur, tidak akan dijanjikan lebih)
- Lossless ada batas entropi: file yang sudah terkompresi tidak bisa dikecilkan
  berarti oleh archiver lossless mana pun, termasuk RAR/7z.
- Wilayah menang kita: teks, kode, log, JSON/XML, dump database, executable,
  banyak file kecil, file duplikat/mirip, data repetitif.
- Harga rasio ekstrem: waktu kompresi + RAM besar (dictionary 1 GB).
  Asimetri Zstd membuat dekompresi tetap cepat — harga dibayar pembuat arsip saja.
- Rekompresi khusus lossless (JPEG ala Lepton/packJPG, PNG recompress) = modul v3 terpisah.

### Hasil benchmark lokal (15 Nov 2026, VM ini, corpus nyata)
Corpus A: 6.410.240 byte teks/kode (repo superpowers+ponytail+remote-jobs, solid tar)
Corpus B: 9.994.240 byte biner (folder WinRAR: exe/dll, solid tar)
Corpus C: 400 file .md kecil, total 611.765 byte

| Metode | A teks | B biner | Catatan |
|---|---|---|---|
| gzip -9 | 21,0% | 54,3% | baseline lemah |
| bzip2 -9 | 15,7% | 54,5% | bagus di teks, runtuh di biner |
| zstd -3 | 19,6% | 48,7% | 0,04-0,07 detik — mode fast |
| zstd -19 | 16,0% | 34,4% | |
| zstd -22 | — | 33,7% | |
| brotli q11 | 15,6% | 36,2% | sangat lambat di biner (34,6 dtk) |
| **xz -9e (LZMA2)** | **15,6%** | **32,2%** | pemenang rasio di kedua corpus |

| Corpus C | Hasil |
|---|---|
| per-file gzip-9 / zstd-19 | 54,6% / 54,7% |
| **SOLID zstd-19** | **28,7%** |
| **SOLID xz-9e** | **28,0%** |

Kesimpulan terverifikasi:
1. Tidak ada satu engine terbaik — makanya Ultra memakai best-of (Zstd-22 vs LZMA2-9e per grup).
2. Efek terbesar BUKAN ganti algoritma, tapi SOLID: file kecil menyusut hampir 2x lipat
   (54,7% -> 28,0%) hanya karena di-stream jadi satu. Ditambah grouping + trained dictionary,
   ini wilayah di mana kita mengalahkan setting default WinRAR/7-Zip.
3. Di biner, LZMA2 mengalahkan gzip 54,3% -> 32,2% (arsip 40% lebih kecil dari ZIP/gzip).

---

## 9. STATUS: v0.1 SELESAI DIBANGUN (15 Nov 2026) — Go

Keputusan Commander: instal Go dulu, langsung bangun versi Go dari awal. SELESAI.

- Toolchain: Go 1.27.4 linux/amd64 di ~/go-toolchain (SHA-256 tarball terverifikasi vs go.dev).
- Kode: ~/workspace/adit-archiver (main.go, format.go, write.go, read.go, codec.go),
  dependensi klauspost/compress v1.20.4 (zstd) + ulikunitz/xz v0.5.17 (LZMA2 murni Go).
  Binary: ~/workspace/adit-archiver/adit (5,3 MB). Perintah: a / x / l / t, mode -m1/-m3/-m5.
- Terimplementasi: solid grouping (kategori PE disatukan), dedup SHA-256, best-of
  Zstd / Zstd+dict terlatih / LZMA2 per grup, store fallback, index JSON TERKOMPRESI
  di akhir + footer, ekstraksi aman (tolak absolut/..), verifikasi SHA-256 saat x/t.

### Hasil terverifikasi (roundtrip diff -r IDENTIK di semua corpus, test SHA-256 OK)
| Corpus | .adit -m5 | ZIP -9 | tar.gz -9 | tar.xz -9e |
|---|---|---|---|---|
| Campuran 4.855.566 B (400 md + 2 exe) | 45,4% | 55,3% | 52,0% | 40,0% |
| Teks murni 607.086 B (399 file kecil) | 31,8% | 60,9% | - | 27,0% |
| Folder WinRAR 9.933.280 B | 37,1% | 54,8% | - | 32,4% |

Menang telak vs ZIP/gzip di semua corpus. Masih kalah ~13-15% dari xz-utils -9e:
penyebab teridentifikasi = kematangan encoder C (matcher bt4) vs LZMA2 murni Go
(HashTable4) + zstd best. Bukan kekalahan desain format.

### Bug/pelajaran selama pembangunan (sudah diperbaiki)
1. LZMA2 BinaryTree ulikunitz patologis lambat (>4 menit, 4,2 MB biner, tidak selesai)
   -> diganti HashTable4: grup sama selesai ~1 detik, hasil praktis setara.
2. BuildDict klauspost butuh field History (isi dictionary), bukan cuma Contents;
   dan bisa PANIC pada sampel biner besar -> dibungkus recover + hanya untuk file kecil.
3. Index JSON mentah = ~80 KB per 400 entri, merusak rasio file kecil -> index dikompresi zstd.
4. Grouping per ekstensi persis membuang redundansi lintas binary PE -> kategori .pe disatukan
   (grup PE WinRAR: 9.377.408 -> 3.280.435 = 35,0%).

### Pekerjaan v0.2 (untuk mengejar/melewati xz)
- Index biner (hash 32 byte biner, bukan 64 char hex) — potong ~ separuh overhead index.
- Backend LZMA2 lebih kuat: cgo liblzma (bt4, preset -9e asli) sebagai kandidat best-of tambahan.
- Streaming decode per grup besar (sekarang grup didecode utuh ke RAM).
- Lalu: enkripsi AEAD + Argon2id, split volume, recovery Reed-Solomon.

---

## 10. STATUS: v0.2 SELESAI (15 Nov 2026) — RENAMA: zulip / .zynx

Perintah Commander: lanjutkan v0.2 + nama app ditetapkan **zulip**, ekstensi **.zynx**.
CATATAN: "Zulip" sudah dipakai aplikasi team-chat open-source terkenal (zulip.com) —
risiko kebingungan/trademark bila dipublikasikan; nama dipertahankan sesuai perintah,
peringatan ini dicatat permanen di sini dan di README.

- Proyek pindah: ~/workspace/zulip-zynx (sebelumnya adit-archiver). Binary: `zulip` (8,8 MB).
- Format v2: magic ZYNX\x1a\x02\x00\x00, footer ZYNX\x1aEND, INDEX BINER (hash 32 byte
  biner, tanpa kunci JSON). Reader tetap membaca .adit v0.1 (magic/footer ADIT, index JSON)
  — TERUJI: test + ekstrak 3 arsip v0.1 identik.
- Backend cgo liblzma DIBATALKAN: header lzma.h tidak ada di VM + cgo merusak portabilitas
  binary statis. Diganti kandidat murni Go yang ternyata lebih kuat: Brotli q11
  (andybalholm/brotli v1.3.0) + filter BCJ x86 (ditulis ulang dari konsep filter xz,
  transformasi reversibel E8/E9, self-verify per grup sebelum tulis).
- Streaming decode: ekstrak/test mengalir per entri (grup BCJ satu-satunya yang masih
  didecode utuh ke RAM). Self-verify: kandidat ultra didecode+ dibandingkan sebelum dipilih.

### Hasil v0.2 terverifikasi (roundtrip diff -r IDENTIK semua corpus, SHA-256 OK)
| Corpus | .zynx -m5 v0.2 | .adit -m5 v0.1 | ZIP -9 | tar.xz -9e |
|---|---|---|---|---|
| Campuran 4.855.566 B | 40,5% (1.966.724) | 45,4% | 55,3% | 40,0% |
| Teks 607.086 B | 28,0% (169.886) | 31,8% | 60,9% | 27,0% |
| Folder WinRAR 9.933.280 B | 32,9% (3.263.190) | 37,1% | 54,8% | 32,4% |

- Brotli q11 = pemenang mengejutkan: menang di grup .md (147.903 vs zstd 169.598) DAN
  grup PE (WinRAR: 2.866.635 vs zstd+bcj 3.261.291 vs lzma2 3.280.435+). BCJ hanya menang
  tipis saat brotli tidak ikut (batas grup 16 MB untuk brotli).
- Gap vs xz-utils -9e menyusut dari ~13-15% (v0.1) menjadi ~1-4% relatif — praktis setara.
- Harga: ultra WinRAR corpus 51 detik (brotli 9,3 MB PE). -m3 tetap jalur cepat.

### Antrian berikutnya (v0.3)
- Enkripsi AEAD (XChaCha20-Poly1305 / AES-256-GCM) + Argon2id, opsi enkripsi header.
- Split multi-volume + recovery record Reed-Solomon + repair.
- Streaming BCJ, SFX stub, GUI/shell integration.

---

## 11. STUDI TOOLS LAIN (15 Nov 2026) — izin Commander dipakai

Commander membebaskan akses tools kompresi lain + menawarkan mencarikan zip-nya.
Sebagian besar berhasil diunduh & dibedah SENDIRI dari sumber resmi (folder
~/workspace/study/compression/), tanpa membebani Commander:

| Bahan | Sumber | Status |
|---|---|---|
| Source 7-Zip 25.01 + DOC (7zFormat.txt, Methods.txt) | 7-zip.org | OK — dan 7za BERHASIL DIBUILD dari source di VM ini |
| LZMA SDK 25.01 + 7z extra (binary Windows) | 7-zip.org | OK — diekstrak pakai 7za hasil build (py7zr gagal: SDK-nya sendiri memakai BCJ2) |
| zstd 1.5.7 source + spek format | GitHub facebook/zstd | OK |
| zpaq 7.15 source + readme | mattmahoney.net | OK |
| FreeArc Next (repo FA, dokumen arsitektur) | GitHub Bulat-Ziganshin | OK sebagian — isinya dokumen/rencana, bukan source klasik |
| paq8px + cmix source | GitHub | OK |

### Bar TERUKUR baru: 7z asli -mx=9 (7za hasil build, BUKAN proksi tar.xz)
| Corpus | 7z -mx=9 | .zynx -m5 v0.2 | waktu 7z |
|---|---|---|---|
| Teks 607.086 B | 26,4% (160.131) | 28,0% | 0,2 dtk |
| Campuran 4.855.566 B | 37,3% (1.811.693) | 40,5% | 1,1 dtk |
| WinRAR 9.933.280 B | 29,9% (2.973.421) | 32,9% | 2,3 dtk |

7z masih menang 6-9% relatif DAN jauh lebih cepat. Senjata utamanya (dari Methods.txt
+ 7zFormat.txt): LZMA2 matcher bt4 kelas C, filter BCJ2 (4 stream terpisah:
kode utama + target E8 + target E9 + sisa), filter Delta, PPMd untuk teks,
header terkompresi + folder/coder chain yang fleksibel, 7zAES (AES-256 + SHA-256 KDF).

### Peta adopsi untuk zulip (antrian teknis, urut dampak)
1. Filter DELTA (stride 1-32, best-of) — murah dibuat, menang di WAV/numerik/tabular. v0.3.
2. BCJ2 versi kita — pisahkan stream target E8/E9 dari stream kode sebelum kompresi;
   target realistis menutup separuh gap PE vs 7z. v0.3.
3. LZMA2 matcher lebih kuat — pekerjaan terbesar; alternatif jangka pendek: kandidat
   "PPMd-like untuk teks" ditunda (brotli sudah dekat), fokus di PE + delta dulu.
4. Dari zpaq: dedup fragment content-defined (FastCDC) + jurnal versi untuk mode backup. v0.4.
5. Dari PAQ/cmix: context mixing = plafon rasio absolut, TIDAK praktis untuk archiver
   umum (menit-menit per MB, RAM raksasa) — dicatat sebagai batas teori, bukan target produk.
6. Dari FreeArc (belum dapat implementasi klasiknya): filter REP (long-range duplicate
   finder ala rzip) + filter multimedia MM — satu-satunya teknik besar yang belum kupelajari
   dari implementasi aslinya.

### Yang masih dibutuhkan dari Commander (gagal diunduh bersih sendiri)
1. **FreeArc 0.67 klasik (arc.exe) — zip portable Windows.** Nama file umumnya
   FreeArc-0.67-alpha-win64.zip / FreeArc_portable. Situs resmi berantakan, tautan
   SourceForge yang kucoba 404. Ini satu-satunya bahan wajib yang belum kudapat.
2. Opsional: binary release paq8px Windows (zip dari GitHub Releases-nya) — menghemat
   waktu build C++ bila mau kubenchmark plafon PAQ di corpus kita.
Selain dua itu: TIDAK ada lagi yang perlu dicarikan. Sisanya sudah di tangan.

---

## 12. BEDAH FREEARC 0.67 + PAQ8PX (kiriman Commander, 15 Nov 2026)

Kedua zip ternyata SOURCE dari GitHub (lebih berguna daripada binary):
- FreeArc-0.67-main.zip — SHA-256 32d6ab2c...f1059ef1cd9, 581 file: source FreeArc 0.67
  lengkap (Haskell shell + library C++ Compression/). Commit 537e4ff.
- paq8px-master.zip — SHA-256 a18b6435...d4a7b, source paq8px master; file utama
  MD5-IDENTIK dengan yang sudah diunduh sendiri (e1c6e253...) — tidak ada materi baru,
  berfungsi sebagai konfirmasi.

### Arsitektur FreeArc yang terungkap (Compression.hs: builtinMethodSubsts)
FreeArc TIDAK memakai satu metode — ia memakai RANTAI METODE PER TIPE FILE:
- Mode tertinggi (x/9): `#rep+exe+#xb / $obj=#b / $text=#t` — chain berbeda untuk
  $obj, $text, $wav, $bmp, $compressed, dipilih dari tipe file.
- Chain teks (#t): `dict:p:128m:80% + lzp:160m:145:d1m:s32:h23:92% + ppmd:16:384m`
  = Dict (preprocessing kamus kata) -> LZP dictionary raksasa -> PPMd orde 16 / 384 MB.
- Chain biner: REP dulu, lalu `delta + lzma:254m:max`; executable dilewatkan filter
  `exe` (= BCJ) atau `dispack` (DisPack).
- REP (level 9: rep:2040m): preprocessor pencari duplikat jarak jauh berbasis hash,
  jendela efektif sampai ~2 GB — menambal batas dictionary LZMA (64-256 MB) dengan
  mengganti pengulangan jauh menjadi referensi SEBELUM kompresor utama bekerja.
- SREP 3.93 (penerus REP, ada di source): "huge-dictionary LZ77 preprocessor" +
  compress_cdc.cpp = CONTENT-DEFINED CHUNKING (rolling hash polynomial) untuk
  menemukan batas chunk — inilah cikal-bakal dedup fragment modern.
- DisPack: filter executable berbasis DISASSEMBLER sungguhan (mem-parse instruksi
  x86 dari alamat origin), bukan pencocokan pola byte seperti BCJ/BCJ2 — level di atas BCJ2.
- MM: filter multimedia (deteksi WAV/BMP, TTA untuk audio lossless).
- Tornado: LZ77 + optimal parsing karya Bulat (engine cepat keluarga tor).
- GRZip: BWT untuk teks level menengah. 4x4: pembungkus blok paralel.

### Peta adopsi zulip — REVISI FINAL untuk v0.3 (urut dampak/biaya)
1. DELTA filter (dari 7z + FreeArc: delta ada di chain biner default FreeArc) —
   murah, langsung buat. Kandidat filter per grup non-PE, stride best-of.
2. REP-LITE ala SREP: dedup chunk content-defined (FastCDC + rolling hash) di dalam
   grup solid sebelum codec — serangan langsung ke data repetitif/backup dan ke
   batas window kompresor. Ini senjata terbesar yang belum kita miliki.
3. BCJ2 versi kita (stream E8/E9 terpisah) untuk grup PE; DisPack penuh ditunda
   (disassembler x86 = proyek tersendiri).
4. Formalisasi CHAIN PER TIPE seperti FreeArc: grup teks/biner/media masing-masing
   punya rantai kandidat sendiri (struktur grup kita sudah 80% ke sana).
5. PPMd/LZP untuk teks: DITUNDA — brotli q11 kita sudah dekat; kerjakan setelah 1-3.
6. PAQ context mixing tetap plafon teori (model per konteks: teks, JPEG, record, dll.
   + mixer neural) — bukan target produk archiver umum.

Status bahan studi: LENGKAP. Tidak ada lagi zip yang dibutuhkan.
Berikutnya: bangun v0.3 (enkripsi AEAD sesuai antrian lama + delta + REP-lite),
atau delta+REP-lite dulu baru enkripsi — urutan diputuskan Commander.

---

## 13. v0.3 SELESAI (15 Nov 2026) — Delta + BCJ2 + REP-lite + Enkripsi

Commander memilih "semua sekaligus". Yang dibangun:

### Format v3
- Magic `ZYNX\x1a\x03`, 1 byte flags (bit0=enkripsi), bila terenkripsi:
  salt 16B + parameter Argon2id (uvarint x3). Index biner v3 menambah
  1 byte stride per grup. Reader tetap membaca v2 dan v1 (.adit).
- Enkripsi: AES-256-GCM per segmen grup + segmen index (nama file
  tersembunyi), kunci Argon2id (t=3, 64MB, 4 thread). CLI: `-p<password>`
  / `--password` / env `ZYNX_PASSWORD`. Arsip terenkripsi dibaca utuh
  per grup (tag GCM diverifikasi sebelum data dipakai).

### Filter baru (filters.go, semua lulus uji unit roundtrip)
- Delta stride 1..32 (encode: selisih byte sejarak stride).
- BCJ2 versi sendiri: stream kode dipisah dari stream target CALL (E8),
  JMP (E9), Jcc (0F 8x); operand diubah relatif->absolut di stream
  samping. Bug nyata ditemukan uji sintetis: opcode literal di ekor
  stream (<5/6 byte sisa) ambigu — diperbaiki dengan "aturan ekor"
  (sisa output == sisa input, opcode di ekor pasti literal).
- REP-lite: token stream copy jarak jauh (hash 4-byte, maks 4 kandidat,
  match minimum 64, jendela = seluruh grup) ala REP/SREP FreeArc.

### Sistem kandidat Ultra v0.3 — dua pelajaran mahal
1. Gerbang global ("codec mahal hanya bila mengalahkan best saat ini")
   SALAH: delta2+zstd (4.80MB) kalah dari brotli polos (5.20MB) sehingga
   delta2+brotli (4.08MB, pemenang sejati) tidak pernah dicoba.
   Diperbaiki menjadi eskalasi PER-CODEC: filter dieskalasi bila
   zstd-terfilter mengalahkan zstd polos >= 1%.
2. Saringan stride delta dengan zstd SpeedDefault BUTA: terukur
   SpeedFastest/SpeedDefault klauspost mengembalikan ukuran ~mentah
   untuk data delta PCM di semua stride (matcher cepatnya menyerah pada
   distribusi byte hasil delta), sedangkan SpeedBetter/Best memampatkan
   normal. Saringan kini memakai SpeedBetterCompression.

### Hasil akhir (corpus di testdata/, roundtrip identik semua)
| Corpus | v0.3 -m5 | 7z -mx9 | Pemenang grup kunci |
|---|---|---|---|
| WAV PCM 6,000,044 | 4,079,259 (68.0%) | 4,244,893 (70.7%) | brotli+delta2 — MENANG vs 7z |
| WinRAR 9,933,280 | 3,263,256 (32.9%) | 2,973,499 (29.9%) | brotli polos (sama v0.2) |
| Campuran 4,874,733* | 1,916,601 (39.3%) | 1,753,851 (36.0%) | brotli polos |
| Teks 629,586* | 120,981 (19.2%) | 103,007 (16.4%) | data grup 102,451 ≈ 7z; kalah overhead index ~18KB |

*Corpus teks/campuran DIBANGUN ULANG 15 Nov (VM berganti, /tmp terhapus;
corpus kini permanen di testdata/). Angka v0.2 untuk corpus lama
(40.5/28.0/32.9) tetap tercatat di §11 sebagai riwayat.
- REP-lite & BCJ2 terverifikasi benar (unit test + self-verify per grup)
  tetapi belum pernah menang di corpus uji: window Zstd (128MB) dan
  Brotli menutupi skala grup saat ini. REP adalah senjata skala besar
  (>64-128 MB per grup), bukan skala corpus ini — dinyatakan apa adanya.
- Enkripsi lulus seluruh uji: tanpa password ditolak, password salah
  gagal di tag GCM, nama file tidak bocor ke ciphertext (grep=0),
  1 byte diubah (tamper) = arsip ditolak, roundtrip identik.
- Kompatibilitas mundur terverifikasi terhadap arsip v0.2/v0.1 asli
  (6 arsip, semua lulus `t`) sebelum /tmp terhapus.

### Antrian v0.4 (sisa roadmap)
1. Index ramping untuk ribuan file kecil (delta varint antar entri) —
   temuan nyata dari corpus teks: data menang, overhead kalah.
2. Split multi-volume. 3. Reed-Solomon recovery record + repair.
4. Streaming decode untuk grup berfilter. 5. SFX stub.

---

## 14. v0.4 SELESAI (15 Nov 2026) — Index ramping, streaming filter, volume, recovery, SFX

Commander memerintahkan "lanjutkan" — seluruh antrian §13 dikerjakan.

### 1. Index biner v4 (format v4, magic ZYNX\x1a\x04)
Entri diurutkan: dir -> fisik per (grup, offset) -> ref (Ref di-remap).
Per entri: byte flags, nama terkompresi prefix (panjang prefix bersama +
suffix), waktu ModUnix delta berantai, grup & offset delta, hash 32B
HANYA untuk entri fisik. Hasil jujur: corpus docs ultra 120.981 -> 120.406
byte (-575). Kecil — karena segmen index memang sudah dizstd; redundansi
nama/waktu sebagian besar sudah dimakan zstd. Sisa selisih vs 7z pada
corpus teks (~17 KB) praktis adalah harga SHA-256 per file (12,8 KB untuk
400 file) melawan CRC-32 7z. Itu harga integritas yang disadari, bukan bug.

### 2. Streaming decode grup berfilter
Delta dan BCJ kini didecode streaming (deltaStreamReader jendela sirkular;
bcjStreamReader dengan holdback tepi buffer), dibuktikan setara dengan
decode buffered pada uji drip-reader 1 byte. BCJ2 tetap buffered (stream
samping tersimpan setelah stream utama — penggabungan butuh akses acak)
dan REP tetap buffered (riwayat salin sejauh grup). Arsip terenkripsi
tetap utuh per grup (AEAD).

### 3. Multi-volume (-v<ukuran>, mis. -v10m / -v500k)
File <arsip>.001, .002, ... masing-masing berheader tetap 32 byte
(magic ZYNXVOL + nomor + panjang payload). Reader menggabungkan volume
menjadi satu ruang byte logis transparan (buka via nama dasar atau .001).
Volume hilang di tengah rangkaian terdeteksi eksplisit
("volume N hilang dari rangkaian"). Uji: docs @50k -> 3 volume,
roundtrip identik.

### 4. Recovery record Reed-Solomon (-r<persen>) + perintah repair
Blok 4096 (16384 bila arsip >32 MB), tabel CRC32 per blok untuk menemukan
kerusakan, paritas RS per stripe 200 blok data (batas GF(2^8) klauspost
reedsolomon). Segmen menempel setelah footer + trailer 32B "ZYNXREC";
reader biasa membatasi view ke wilayah tercakup. `zulip repair`
memindai, merekonstruksi blok rusak per stripe, menulis hanya blok itu,
lalu memverifikasi ulang. Teruji: kerusakan 2 blok di data dan kerusakan
blok terakhir (index/footer) pulih byte-identik (cmp); kerusakan melebihi
paritas ditolak dengan pesan jelas; bekerja juga pada arsip terenkripsi.
Batas jujur: segmen recovery sendiri (tabel CRC/paritas) tidak ikut
dilindungi — kerusakan di sana bisa menggagalkan repair.
Bug nyata yang ditemukan & diperbaiki: pembacaan blok terakhir harus
dibatasi sisa wilayah tercakup, bukan blockSize penuh (ReadAt membaca
meluber ke segmen recovery dan blok terakhir selalu tampak rusak).

### 5. SFX (--sfx)
Keluaran = [binary zulip][arsip][trailer 16B: offset + magic ZYNXSFX].
Dijalankan tanpa argumen -> auto-extract ke folder saat ini; dibuka via
perintah zulip biasa juga bisa (deteksi trailer di openSource).
Tidak bisa digabung multi-volume (ditolak eksplisit).

### Hasil ultra v0.4 (corpus testdata, roundtrip identik)
docs 120.406 (19,1%) | mix 1.916.036 (39,3%) | winrar 3.263.182 (32,9%)
— sama seperti v0.3 di data, lebih kecil di index; fitur adalah bintangnya.
Seluruh arsip v0.3 (termasuk terenkripsi) tetap terbaca binary v0.4.
Suite uji Go: filter, index v4, streaming, crypto, recovery — semua lulus.

### Antrian berikutnya (belum ada perintah)
- Matcher LZMA2 lebih kuat / kandidat PPMd untuk teks (mengejar 7z di PE & teks).
- Recovery untuk multi-volume; perlindungan segmen recovery (CRC atas segmen).
- SFX untuk Windows (stub .exe) bila proyek dipublikasikan.

---

## 15. v0.5 SELESAI (15 Nov 2026) — Hardening: blok 32 MB, streaming tulis, atomik, fuzz, soak 1,13 GB

Commander menyetujui penilaian "layak harian setelah satu milestone
hardening" dan memerintahkan v0.5 segera. Isi:

### Format v5: grup = rantai blok solid independen (maks 32 MB mentah)
- Index v5 menyimpan metadata per blok (codec/filter/stride/ukuran);
  skema entri mewarisi v4. Segmen grup: [chunk dict bila ada][blok...];
  terenkripsi: per chunk [uvarint][sealed AES-GCM] (dulu: segel utuh).
- Penulis: fase hash kini streaming (isi file tidak pernah dimuat utuh);
  grup dirakit dari disk per blok, blok di-encode (encodeBlock = logika
  kandidat lama, kini per blok) lalu di-spool ke file sementara.
  RAM penulis terbatas ~satu blok + kandidat (bukan sebesar arsip).
- Pembaca: blockChainReader malas menyambung decode blok per blok untuk
  SEMUA jalur v5 (polos, berfilter, terenkripsi). Jalur v1-v4 tidak berubah.
- Harga: +7 byte pada corpus docs ultra (120.406 -> 120.413, metadata blok);
  grup <= 32 MB praktis identik dengan v0.4.

### Tulis atomik
Semua keluaran (file tunggal, volume, SFX) ditulis ke nama sementara
lalu di-rename di ujung; kegagalan membersihkan sementaranya. Teruji:
proses dibunuh (kill -9) di tengah penulisan arsip 1,13 GB — arsip lama
di path tujuan byte-identik dan tetap sehat; hanya sisa .tmp-zynx tertinggal.

### Fuzz & uji tepi (fuzz_test.go, edge_test.go)
- FuzzUnmarshalIndex 25 dtk: 192.665 eksekusi, bersih.
- FuzzOpenArchive menemukan SATU panic nyata: indexOffset footer negatif/
  keluar file -> makeslice len out of range di openArchive. Diperbaiki
  dengan validasi offset sebelum alokasi + pagar kewajaran di groupDict,
  readGroupPlain, dan chunk dict/blok terenkripsi blockChainReader;
  detectRecovery juga dikeraskan (konsistensi DataBlocks vs CoveredLen).
  Fuzz ulang 30 dtk bersih; kasus tabrakan lama jadi regression seed.
- TestCorruptNeverPanics: semua prefix terpotong + 300 korupsi acak +
  byte acak murni — tidak ada panic, hanya error.
- TestEdgeCasesMultiBlock: dir kosong bersarang, nama Unicode & 175 char,
  file kosong, file 40 MB nol + 2x20 MB pola (blok terbelah di tengah
  file dan antar file) — roundtrip identik.

### Soak test 1,13 GB (corpus generator seed 99, sudah dibersihkan)
- Buat (-m3): 1.131.416.240 -> 88.660.156 byte (7,8%), 103 dtk,
  puncak RSS 524 MB (didominasi jendela encoder zstd per blok).
- Test: 2,4 dtk, puncak RSS 102 MB. Ekstrak: 4,7 dtk, RSS 102 MB,
  diff -r identik. Grup .bin 944 MB terpecah 29 blok; .pe 188 MB 6 blok.
- Ultra multi-blok terverifikasi: file 500 MB -> 16 blok, 13,8%,
  integritas OK (lambat: ~5,7 menit — harga kandidat LZMA2 per blok).

### Penilaian kelayakan (per 15 Nov 2026)
Layak pakai harian untuk data pribadi Commander di Linux: fungsi lengkap,
RAM terbatas terukur, atomik, reader tahan arsip rusak (fuzz), kompatibel
mundur ke v0.1. Belum untuk publik: uji Windows/macOS, stub SFX Windows,
dan keputusan nama "Zulip" masih terbuka (lihat catatan README).

---

## 16. v0.6 SELESAI (15 Nov 2026) — Ronde UI/UX: lebih baik dari alat kompresi lain, dengan bukti

Commander memerintahkan UI/UX zulip dipastikan lebih baik dari alat
kompresi lain, memakai 4 skill yang baru dipasang. Metode: prinsip
diambil dari basis data UI/UX Pro Max (query "progress indicator
loading feedback" dan "error message recovery", domain ux), aturan
Emil Kowalski (gerak mengikuti frekuensi pakai; detail kecil yang
menumpuk), gerbang Anti-Slop (mode DURING diumumkan, audit AFTER di
bawah), dan Taste (hierarki, konsistensi, tanpa dekorasi tanpa guna).
Arena perbandingan yang jujur: zulip adalah CLI, jadi pembanding utama
adalah keluaran bawaan 7z CLI dan rar CLI, dengan GUI WinRAR/7-Zip FM
dan Keka sebagai konteks.

### Audit pembanding (kualitatif, dari keluaran bawaan masing-masing)
| Kriteria | 7z CLI | rar CLI / WinRAR | zulip v0.6 |
|---|---|---|---|
| Umpan balik operasi lama | % kasar, tanpa laju/ETA | persen per file, bising | bar + % + laju + sisa waktu |
| Angka | byte mentah | byte/KB tak konsisten | selalu satuan manusia, koma desimal ID |
| Error | kriptik ("CRC Failed") | kode nomor | pesan jelas + baris "Petunjuk:" berisi jalan keluar |
| Timpa berkas | prompt Y/N/A/S/Q tanpa konteks | dialog GUI | prompt 4 pilihan berlabel (timpa/lewati/semua/batal); non-TTY tetap perilaku skrip |
| Ringkasan akhir | blok statistik mentah | log panjang | kartu 4 baris: arsip, isi, rasio + bar visual, langkah lanjut |
| Di-pipe/diskrip | bersih | bersih | bersih: warna & progress hanya di TTY, NO_COLOR dihormati |
| Bantuan | dinding opsi | - | berkelompok + contoh nyata + catatan |

### Yang dibangun (ui.go + sentuhan di main/write/read)
- Deteksi TTY per aliran (stdout warna, stderr progress, stdin prompt);
  NO_COLOR dan TERM=dumb dihormati; warna semantik dan tidak pernah
  menjadi satu-satunya pembawa arti (selalu ada simbol/teks: centang,
  silang, panah).
- Progress dua fase buat arsip (Memindai -> Mengompres), satu fase uji
  dan ekstrak: bar 24 kolom + persen + byte berjalan/total + laju +
  ETA, throttle 120 ms, digambar di stderr agar stdout tetap bersih.
- humanSize/humanDur/percentID: "1,05 GB", "1 mnt 43 dtk", "7,8%".
- Kartu ringkasan pembuatan arsip + bar rasio; daftar isi menjadi
  tabel (UKURAN | DIUBAH | NAMA) dengan footer total; ringkasan uji
  dan ekstrak satu baris berisi jumlah, durasi, dan status hash.
- Keamanan UX: buat arsip menimpa arsip lama kini bertanya dulu di
  terminal (bawaan: tidak); ekstrak bertanya per berkas yang sudah ada.
- Error dengan petunjuk pemulihan untuk kasus dikenal (kata sandi,
  volume hilang, bukan arsip, checksum rusak -> arahkan ke repair,
  path tidak ditemukan); kasus tak dikenal dicetak apa adanya.
- Help ditulis ulang: kelompok perintah, mode, opsi, 4 contoh, catatan.

### Gerbang Anti-Slop (audit AFTER) — PASS semua
- Hard Gate: tidak ada angka karangan (semua nilai dari run nyata);
  semua kontrol berfungsi (flag dan prompt t/l/s/b teruji di TTY via
  script(1)); progress mencerminkan byte nyata dari hook flushBlock/
  processGroup; aksesibilitas lulus (NO_COLOR, pipe bersih).
- Purpose-Gate: warna = pemindaian status semantik; bar+ETA = kewajiban
  umpan balik untuk tunggu panjang; bar rasio = data, bukan dekorasi;
  prompt = mencegah kehilangan data senyap.
- Liveliness: dial CLI ENERGY 2, RHYTHM 2, MOTION 1 — keluaran
  konsisten dengan dial (gerak hanya progress, itu pun hanya di TTY).
- Quality Locks: istilah konsisten (arsip/entri/grup), satuan dan koma
  desimal Indonesia di semua perintah, kolom rata.

### Verifikasi
Suite Go penuh hijau. Demo TTY via script(1): prompt timpa arsip dan
berkas tampil, progress mencapai 100,0% berwarna, ringkasan tercetak;
demo non-TTY: teks bersih tanpa kode ANSI. Petunjuk error terverifikasi
untuk kata sandi salah, berkas hilang, dan arsip palsu. Ukuran arsip
tidak berubah oleh ronde ini (murni lapisan tampilan): docs ultra
tetap 120.413 byte.

---

## 17. Build Windows (15 Nov 2026) — paket uji untuk device Commander

Commander meminta exe/installer untuk menguji sendiri di device-nya.
Dibangun dari source yang sama persis dengan build Linux v0.6.0
(suite Go penuh hijau sebelum cross-compile):

- `dist/zulip-0.6.0-windows/zulip.exe` — PE32+ console x86-64, 8,2 MB,
  CGO nonaktif, tanpa dependensi. SHA-256
  3621df7ed5454006581fe450d8b44863ce53f0348b37f29d3dbd9af80b38ee35.
- `dist/zulip-arm64.exe` — PE32+ Aarch64 untuk Windows on ARM.
- Penyesuaian Windows: ui_windows.go mengaktifkan
  ENABLE_VIRTUAL_TERMINAL_PROCESSING agar warna/progress v0.6 tampil
  benar di conhost; nama entri arsip sudah selalu garis miring
  (filepath.ToSlash sejak awal) sehingga arsip portabel antar-OS.
- Paket: zulip.exe + install.bat (salin ke %LOCALAPPDATA%\Programs\
  zulip + PATH pengguna via PowerShell, tanpa admin) + uninstall.bat
  + BACA-DULU.txt (langkah uji kompres/ekstrak) + README, dibungkus
  .zip (dan .zynx sebagai bonus). SmartScreen diperkirakan muncul
  karena exe belum bertanda tangan — didokumentasikan di BACA-DULU.
- Batas verifikasi: VM ini tidak punya Wine, jadi binary Windows
  TIDAK dijalankan di sini — validasi berhenti di PE valid + source
  identik yang lulus seluruh suite di Linux. Uji runtime di device
  Commander adalah langkah verifikasi yang memang dimintanya; hasil
  uji (terutama prompt interaktif, warna konsol, dan SFX Windows)
  menentukan apakah item "uji Windows" di penilaian publik tertutup.

---

## 18. v0.7.0 (15 Nov 2026) — GUI Windows + integrasi Explorer

Umpan balik uji device Commander atas paket v0.6.0: kompres bekerja,
tetapi (1) tidak ada menu klik kanan seperti ZIP/WinRAR, (2) berkas
.zynx tidak bisa diekstrak dari Explorer (belum ada asosiasi/GUI —
ekstrak baru bisa lewat perintah x di terminal), (3) belum ada GUI
seperti WinRAR. Ketiganya dibangun dalam ronde ini:

### CLI: mode daftar JSON (untuk GUI)
`zulip l --json <arsip>` mencetak versi format, mode, status enkripsi,
entri (nama/ukuran/dir/modtime/dedup) dan grup (codec/raw/comp) sebagai
JSON. Versi aplikasi naik ke 0.7.0; format arsip tidak berubah.

### GUI native Windows (gui/, lxn/walk, tanpa CGO)
zulip-gui.exe — subsistem GUI, ikon + manifes (Common Controls v6,
DPI-aware) tertanam via rsrc. Jendela utama ala WinRAR: menu Berkas/
Bantuan, tombol Buka/Buat/Ekstrak/Uji/Perbaiki, tabel isi arsip
(Nama/Ukuran/Diubah/Keterangan), bar status ringkasan. Dialog buat
arsip: daftar masukan (tambah berkas/folder/hapus), nama tujuan, mode
(bawaan Ultra), kata sandi, recovery %, volume, SFX; dialog ekstrak:
folder tujuan (bawaan: folder senama arsip di sampingnya) + kata
sandi; dialog kata sandi otomatis saat membuka arsip terenkripsi;
dialog progres menjalankan zulip.exe sebagai proses anak dengan log
langsung + tombol batal yang benar-benar menghentikan proses.
Seret-jatuhkan: berkas .zynx dibuka, berkas lain masuk dialog buat.
Mode integrasi: --open (klik ganda), --extract (menu konteks),
--add (menu konteks kompres). GUI mencari zulip.exe di foldernya
sendiri, jatuh ke PATH bila tidak ada.

Dua perbaikan desain yang ditemukan saat menulis (dicatat agar tidak
terulang): dialog deklaratif walk harus dijalankan lewat literal
Run(owner) agar AssignTo terisi sebelum nilai bawaan dipasang; dan
hasil proses anak pada dialog progres harus diserahkan lewat variabel
bersama yang ditulis satu-satunya goroutine konsumen — dua penerima
pada satu channel membuat error kegagalan tertelan dan pemanggil
mengira operasi berhasil.

### Integrasi Explorer (install.bat, HKCU tanpa admin)
- .zynx -> ProgID Zynx.Archive: ikon dari zulip-gui.exe, verb bawaan
  open -> GUI --open; verb "Ekstrak dengan zulip..." -> GUI --extract.
- * dan Directory: verb "Kompres dengan zulip (.zynx)" -> GUI --add.
- uninstall.bat menghapus semua kunci itu, folder program, dan PATH.
- Catatan jujur: di Windows 11 verb klasik muncul di balik
  "Show more options" (kebijakan Microsoft, bukan kekurangan paket).

### Verifikasi & batasnya
CLI: suite Go penuh hijau; mode JSON terverifikasi. GUI + CLI Windows:
lolos build silang dan go vet untuk target windows/amd64, PE GUI valid
dengan seksi sumber daya tertanam. Percobaan memasang Wine di VM untuk
verifikasi runtime: repositori paket lambat/tidak menyediakan wine64
pada percobaan pertama; percobaan kedua (apt-get update + install)
berjalan di latar. Bila Wine tidak tersedia sampai pengiriman, uji
runtime Windows tetap berada di device Commander — kali ini terhadap
tiga kekurangan yang ia sebutkan secara eksplisit.

---

## 19. v0.7.1 (15 Nov 2026) — perbaikan bug uji device + klik kanan langsung + ikon baru

Laporan uji Commander atas 0.7.0 (dengan tangkapan layar): GUI dan
menu klik kanan bekerja, dialog buat arsip terbuka dari Explorer
dengan masukan terisi — tetapi menekan "Buat arsip" memunculkan
"Nama arsip tujuan belum diisi" padahal kolomnya terisi. Ditambah dua
permintaan: ikon diganti (exe + aplikasi berjalan), dan klik kanan
harus bisa LANGSUNG mengompres seperti RAR/ZIP tanpa masuk aplikasi.

### Akar bug "tujuan belum diisi"
Kontrol walk dibuang (dispose) saat Dialog.Run() kembali; membaca
.Text()/.Value()/.Checked() setelah itu menghasilkan nilai kosong.
Semua dialog kini menyalin nilainya ke struct snapshot di dalam
handler tombol utama SEBELUM Accept() (berlaku untuk buat arsip,
ekstrak, dan kata sandi). Perbaikan pendamping dari tangkapan layar
yang sama: label "Berkas & folder" kehilangan "&" (mnemonic Win32)
dan kolom jalur yang tadinya TextEdit multi-baris kini LineEdit.

### Klik kanan langsung
Mode baru: --quickadd (kompres satu berkas/folder ke .zynx Ultra di
sampingnya, hanya jendela progres, aplikasi menutup sendiri, hasil
ditunjukkan di Explorer) dan --extracthere (ekstrak ke folder senama;
arsip terenkripsi dialihkan ke dialog penuh), plus --test. Registry:
verb "Kompres ke .zynx dengan zulip" (langsung) berdampingan dengan
"Kompres dengan zulip (opsi lanjut)..."; pada .zynx bertambah
"Ekstrak di sini dengan zulip" dan "Uji integritas dengan zulip".

### Ikon baru
Logo diganti total: kepala kucing hitam pemarah bermata sipit emas,
kumis, dan bel emas (mengikuti avatar Jamal pilihan Commander),
digambar programatik (PIL) multi-ukuran. Dipakai sebagai ikon berkas
kedua .exe (rsrc), ikon asosiasi .zynx (DefaultIcon), dan ikon
jendela yang berjalan — yang terakhir dimuat dari PNG tertanam
(go:embed) lewat NewIconFromImage dengan penjaga recover(), BUKAN
NewIconFromResourceId (lihat temuan Wine di bawah).

### Verifikasi Wine (baru pertama kali bisa)
Wine akhirnya terpasang di VM (wine64 + xvfb), sehingga ronde ini
terverifikasi pada runtime Windows sungguhan, bukan hanya build:
- CLI: kompres/uji/ekstrak + arsip terenkripsi roundtrip identik.
- GUI: jendela utama hidup, dialog tambah terbuka, --quickadd
  menghasilkan arsip dan aplikasi menutup sendiri, --extracthere
  mengekstrak, roundtrip via GUI identik byte-per-byte.
- Temuan keras dari proses ini: properti kosmetik TableView
  LastColumnStretched memicu kegagalan LVM_SETCOLUMNWIDTH saat
  Create() di Wine; karena error Create() diabaikan, jendela rusak
  dan Run() langsung kembali — aplikasi mati tanpa pesan. Properti
  itu dibuang, error Create() kini ditangani eksplisit (pesan +
  gui-debug.log di folder exe, dipertahankan permanen untuk
  diagnostik lapangan), dan pemuatan ikon jendela dibuat kebal
  kegagalan. Pelajaran dicatat: di walk, error Create() yang
  diabaikan mengubah kegagalan satu kontrol menjadi aplikasi mati.

---

## 20. v0.7.2 (15 Nov 2026) — berbagi ke non-pengguna: SFX ramping + konversi ZIP

Benchmark device Commander sendiri (folder paket zulip-0.6.0-windows):
.zynx 2.536 KB < .rar 2.677 KB < .zip 3.171 KB — zulip menang dari
RAR dan ZIP di mesinnya. Kendala tersisa yang ia angkat: penerima
tanpa zulip tidak bisa membuka .zynx, tidak seperti ZIP (bawaan OS)
dan RAR (didukung banyak alat). Dua jalan keluar resmi dibangun:

### SFX yang benar-benar terverifikasi + stub ramping
- Perintah baru `zulip sfx <arsip.zynx> [out.exe]` membungkus arsip
  yang sudah ada (sebelumnya SFX hanya bisa dari `a --sfx`).
- Stub khusus ekstrak di stub/ (paket terpisah yang menautkan berkas
  jalur-baca lewat symlink + shims tampilan kecil; nol kode kompres):
  5,6 MB vs zulip.exe penuh 8,5 MB (-32%). wrapSFX otomatis memakai
  zulip-stub.exe di samping executable bila ada, jatuh ke binary
  sendiri bila tidak.
- Uji Wine menemukan bug Windows sungguhan: wrapSFX menghapus berkas
  temp yang masih terbuka (defer Close) -> "sharing violation" di
  Windows; di Linux tidak terlihat. Diperbaiki (Close eksplisit
  sebelum Remove) — bug ini juga mengintai `a --sfx` di device.
- Terverifikasi ujung-ke-ujung di Wine: SFX 5,5 MB dijalankan
  sendirian di folder tanpa zulip -> 400 berkas identik, SHA-256 cocok.

### Konversi ZIP universal
- Perintah baru `zulip tozip <arsip.zynx> [out.zip]` (ekstrak ke temp
  terverifikasi SHA-256, kemas ulang Deflate terbaik) + GUI --tozip +
  verb klik kanan + menu Berkas. ZIP hasil divalidasi zipfile Python
  dan uji GUI-di-Wine (401 entri, testzip bersih). Harga jujur:
  ZIP contoh 274 KB vs .zynx 120 KB — .zynx tetap format arsip,
  ZIP/SFX adalah format berbagi.

### Permukaan Explorer/GUI
Verb baru: pada berkas/folder "Buat SFX .exe dengan zulip (dibuka
tanpa zulip)" (--quicksfx); pada .zynx "Buat SFX .exe untuk
dibagikan" (--tosfx) dan "Konversi ke .zip (universal)" (--tozip);
menu Berkas GUI: "Buat SFX dari arsip ini" + "Ekspor sebagai ZIP".
Label checkbox SFX di dialog buat kini menjelaskan manfaatnya.

---

## 21. v0.8.0 (15 Nov 2026) — kecepatan klik kanan, desain ulang GUI, kesiapan publish

Keluhan Commander: kompres bawaan klik kanan (yang memakai Ultra)
jauh lebih lambat dari ZIP/RAR, GUI perlu diganti/disempurnakan, dan
fitur utama masih jauh dari layak publish global. Data dulu, vonis
kemudian — benchmark VM (CPU ter-throttle 1,5; angka relatif yang
berlaku), corpus WinRAR 9,93 MB: zulip -m1 0,54 dtk/54,0%; -m3
1,73 dtk/37,1%; -m5 117,11 dtk/32,9%; 7za zip -mx5 1,30 dtk/53,6%;
zip -mx9 6,07 dtk/53,1%; 7z -mx5 2,61 dtk/31,2%. Corpus mix serupa.

### Kecepatan
- Akar masalah terukur: klik kanan memakai Ultra (117 dtk) — kandidat
  best-of Brotli q11/LZMA2/BCJ2/Delta/REP dicoba SEkuensial per blok.
- --quickadd & --quicksfx kini memakai profil Normal (-m3): ~1,7 dtk
  pada corpus yang sama, tetap 37% vs ZIP 54%. Ultra tetap bawaan
  dialog opsi lanjut & CLI -m5 (pilihan sadar untuk terkecil).
- Kandidat Ultra dievaluasi paralel (fase A bebas + fase B eskalasi
  per-codec, semaphore NumCPU), consider() diterapkan dalam urutan
  asli: keluaran BYTE-IDENTIK dengan sekuensial (SHA-256 arsip docs
  ultra sama persis dengan build v0.5: 3afd9423…). Di VM 1,5 CPU
  keuntungannya ~10% (117→107 dtk); di mesin multi-core nyata
  skalanya mengikuti jumlah core pada fase kandidat.

### Desain ulang GUI
Pita header hitam (logo kucing 48px dipasang SETELAH Create agar
kegagalan gambar tidak pernah menggagalkan start — pelajaran dari
insiden LastColumnStretched), nama + tagline + versi emas; toolbar
dengan Ekstrak tebal; bar status abu terang; ikon kucing di semua
dialog (pola Create → setFormIcon → Run); dialog Tentang berlogo;
menu Berkas akhirnya benar-benar berisi aksi SFX/ZIP (patch 0.7.2
untuk menu ini ternyata no-op senyap — kini semua patch diasersi);
penjaga panic di main() yang menulis gui-debug.log.

### Kesiapan publish
VERSIONINFO resmi (goversioninfo: ikon + manifes + FileVersion/
ProductName 0.8.0) di zulip.exe (amd64+arm64), zulip-gui.exe, dan
zulip-stub.exe; LICENSE MIT; CHANGELOG.md; suite Go penuh hijau.
Terverifikasi Wine (dipasang ulang setelah VM terganti): GUI baru
hidup, quickadd profil Normal menghasilkan arsip benar dalam hitungan
detik dan aplikasi menutup sendiri. Sisa penghalang publish yang
jujur di luar kode: code signing berbayar (SmartScreen) dan keputusan
nama "zulip" — keduanya dicatat di BACA-DULU paket.
