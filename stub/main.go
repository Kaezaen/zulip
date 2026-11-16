// Stub SFX ramping: hanya bisa MENGEKSTRAK arsip yang menempel pada
// dirinya sendiri (format SFX zulip). Tanpa kode kompres sama sekali
// agar berkas .exe hasil SFX sekecil mungkin.
package main

import (
	"fmt"
	"os"
)

func main() {
	handled, err := maybeSelfExtract()
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗", err)
		fmt.Println("Tekan Enter untuk menutup...")
		var s string
		fmt.Scanln(&s)
		os.Exit(1)
	}
	if !handled {
		fmt.Println("Ini adalah stub pengekstrak zulip. Lampirkan arsip .zynx dengan perintah: zulip sfx <arsip.zynx>")
	}
}
