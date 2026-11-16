// zulip — archiver dengan format .zynx (v0.3)
// Clean-room: format, nama, dan ekstensi sendiri; algoritma terbuka
// (Zstandard + LZMA2 + Brotli). Flagship: mode -m5 ultra — solid grouping,
// dedup, dictionary training, filter BCJ/BCJ2/Delta/REP-lite, best-of
// engine per grup, enkripsi AES-256-GCM + Argon2id opsional.
// Arsip lama .adit v0.1 dan .zynx v0.2 tetap bisa dibaca (l/t/x).
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

const version = "0.8.0"

func usage() {
	fmt.Print(`zulip ` + version + ` — pengarsip .zynx: kompresi maksimum, format terbuka

PERINTAH
  a        buat arsip baru          x   ekstrak arsip
  l        lihat daftar isi         t   uji integritas (SHA-256)
  repair   perbaiki arsip rusak dari recovery record-nya
  version  tampilkan versi

CARA PAKAI
  zulip a [opsi] <arsip.zynx> <file/folder...>
  zulip x [-p<kata sandi>] <arsip[.001]> [folder tujuan]
  zulip l [-p<kata sandi>] <arsip[.001]>
  zulip t [-p<kata sandi>] <arsip[.001]>
  zulip repair <arsip.zynx>
  zulip sfx <arsip.zynx> [keluaran.exe]   bungkus jadi .exe mandiri (penerima tak perlu zulip)
  zulip tozip <arsip.zynx> [keluaran.zip] konversi ke ZIP standar (dibuka OS apa pun)

MODE KOMPRESI (untuk a)
  -m1   fast     Zstd tercepat — untuk file besar yang buru-buru
  -m3   normal   Zstd terbaik per grup (bawaan)
  -m5   ultra    ukuran terkecil: best-of Zstd / Zstd+dictionary /
                 LZMA2 / Brotli + filter BCJ2, Delta, REP-lite;
                 setiap kandidat diverifikasi — paling lambat

OPSI LAIN (untuk a)
  -p<kata sandi>   enkripsi AES-256-GCM + kunci Argon2id;
                   nama file ikut tersembunyi
  -v<ukuran>       pecah multi-volume: -v10m, -v500k -> .001, .002, ...
  -r<persen>       recovery record Reed-Solomon: -r5, -r10
  --sfx            bungkus jadi berkas self-extracting

CONTOH
  zulip a -m5 backup.zynx dokumen/ foto/
  zulip a -m3 -pRahasia123 -r10 data.zynx data/
  zulip x backup.zynx hasil/
  zulip t backup.zynx

CATATAN
  Kata sandi juga bisa dari env ZYNX_PASSWORD (untuk x/l/t).
  Ekstrak di terminal akan bertanya sebelum menimpa berkas yang ada.
`)
}

// extractPassword memisahkan -p<password> / --password <pw> dari argumen.
// Bila tidak ada flag, jatuh ke env ZYNX_PASSWORD.
func extractPassword(args []string) (string, []string) {
	pw := ""
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--password" && i+1 < len(args):
			pw = args[i+1]
			i++
		case strings.HasPrefix(a, "--password="):
			pw = strings.TrimPrefix(a, "--password=")
		case strings.HasPrefix(a, "-p") && len(a) > 2:
			pw = strings.TrimPrefix(a, "-p")
		case a == "-p" && i+1 < len(args):
			pw = args[i+1]
			i++
		default:
			rest = append(rest, a)
		}
	}
	if pw == "" {
		pw = os.Getenv("ZYNX_PASSWORD")
	}
	return pw, rest
}

func main() {
	if len(os.Args) < 2 {
		// Tanpa argumen: bila binary ini SFX, ekstrak isinya.
		if done, err := maybeSelfExtract(); done {
			if err != nil {
				printErrHint(err)
				os.Exit(1)
			}
			return
		}
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "help", "-h", "--help":
		usage()
		return
	case "version", "-v", "--version":
		fmt.Println("zulip", version)
		return
	case "a":
		mode := "normal"
		pw, args := extractPassword(os.Args[2:])
		opts := addOptions{password: pw}
		var rest []string
		for _, a := range args {
			switch {
			case a == "-m1":
				mode = "fast"
			case a == "-m3":
				mode = "normal"
			case a == "-m5":
				mode = "ultra"
			case a == "--sfx":
				opts.sfx = true
			case strings.HasPrefix(a, "-r") && len(a) > 2:
				var perr error
				opts.recoveryPct, perr = strconv.Atoi(a[2:])
				if perr != nil {
					err = perr
				}
			case strings.HasPrefix(a, "-v") && len(a) > 2:
				var perr error
				opts.volumeSize, perr = parseSize(a[2:])
				if perr != nil {
					err = perr
				}
			default:
				rest = append(rest, a)
			}
		}
		if err == nil && len(rest) < 2 {
			err = fmt.Errorf("pakai: zulip a [-m1|-m3|-m5] [-p<password>] [-v<ukuran>] [--sfx] <arsip.zynx> <file/dir...>")
		}
		if err == nil {
			err = cmdAdd(mode, rest[0], rest[1:], opts)
		}
	case "x":
		pw, args := extractPassword(os.Args[2:])
		if len(args) < 1 {
			err = fmt.Errorf("pakai: zulip x [-p<password>] <arsip> [folder_tujuan]")
			break
		}
		dest := "."
		if len(args) >= 2 {
			dest = args[1]
		}
		err = cmdExtract(args[0], dest, pw)
	case "sfx":
		args := os.Args[2:]
		if len(args) < 1 {
			err = fmt.Errorf("pakai: zulip sfx <arsip.zynx> [keluaran.exe]")
			break
		}
		out := ""
		if len(args) >= 2 {
			out = args[1]
		}
		err = cmdWrapSFX(args[0], out)
	case "tozip":
		pw, args := extractPassword(os.Args[2:])
		if len(args) < 1 {
			err = fmt.Errorf("pakai: zulip tozip [-p<password>] <arsip.zynx> [keluaran.zip]")
			break
		}
		out := ""
		if len(args) >= 2 {
			out = args[1]
		}
		err = cmdToZip(args[0], out, pw)
	case "repair":
		if len(os.Args) < 3 {
			err = fmt.Errorf("pakai: zulip repair <arsip.zynx>")
			break
		}
		err = cmdRepair(os.Args[2])
	case "l":
		pw, args := extractPassword(os.Args[2:])
		jsonMode := false
		var rest []string
		for _, a := range args {
			if a == "--json" {
				jsonMode = true
			} else {
				rest = append(rest, a)
			}
		}
		if len(rest) < 1 {
			err = fmt.Errorf("pakai: zulip l [--json] [-p<password>] <arsip>")
			break
		}
		if jsonMode {
			err = cmdListJSON(rest[0], pw)
		} else {
			err = cmdList(rest[0], pw)
		}
	case "t":
		pw, args := extractPassword(os.Args[2:])
		if len(args) < 1 {
			err = fmt.Errorf("pakai: zulip t [-p<password>] <arsip>")
			break
		}
		err = cmdTest(args[0], pw)
	default:
		fmt.Fprintf(os.Stderr, "%s perintah tidak dikenal: %s\n\n", errCol("✗"), os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		printErrHint(err)
		os.Exit(1)
	}
}
