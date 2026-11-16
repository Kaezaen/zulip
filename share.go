package main

// Perintah berbagi: membuat arsip .zynx bisa dibuka oleh orang yang
// TIDAK memasang zulip.
//   - sfx:   bungkus arsip menjadi .exe yang mengekstrak dirinya
//     sendiri di Windows mana pun, tanpa zulip.
//   - tozip: konversi isi arsip ke .zip standar yang bisa dibuka
//     bawaan Windows/macOS/Linux apa pun.

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// cmdWrapSFX membungkus arsip .zynx yang sudah ada menjadi SFX .exe.
func cmdWrapSFX(archivePath, outPath string) error {
	// Arsip multi-volume tidak bisa dibungkus (kepala volumenya beda).
	head := make([]byte, 8)
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	if _, err := io.ReadFull(f, head); err != nil {
		f.Close()
		return fmt.Errorf("arsip terlalu kecil / bukan arsip zulip")
	}
	f.Close()
	if bytes.Equal(head, []byte(volumeMagic)) {
		return fmt.Errorf("arsip multi-volume tidak bisa dijadikan SFX — gabungkan dulu menjadi satu berkas")
	}
	if outPath == "" {
		outPath = strings.TrimSuffix(archivePath, filepath.Ext(archivePath)) + ".exe"
	}
	// wrapSFX menghapus berkas arsip sementaranya; beri salinan.
	tmp, err := os.CreateTemp("", "zulip-sfx-*.zynx")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	src, err := os.Open(archivePath)
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := io.Copy(tmp, src); err != nil {
		src.Close()
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	src.Close()
	tmp.Close()
	if err := wrapSFX(tmpName, outPath); err != nil {
		os.Remove(tmpName)
		return err
	}
	st, _ := os.Stat(outPath)
	fmt.Printf("%s SFX dibuat: %s (%s) — penerima cukup menjalankannya, tanpa zulip\n",
		okCol("✓"), outPath, humanSize(st.Size()))
	return nil
}

// cmdToZip mengekstrak arsip lalu mengemas ulang isinya sebagai .zip.
func cmdToZip(archivePath, outPath, password string) error {
	if outPath == "" {
		outPath = strings.TrimSuffix(archivePath, filepath.Ext(archivePath)) + ".zip"
	}
	tmpDir, err := os.MkdirTemp("", "zulip-tozip-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)
	if err := cmdExtract(archivePath, tmpDir, password); err != nil {
		return err
	}
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(out)
	count := 0
	walkErr := filepath.WalkDir(tmpDir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(tmpDir, p)
		if err != nil || rel == "." {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if d.IsDir() {
			hdr.Name += "/"
			hdr.Method = zip.Store
			_, err := zw.CreateHeader(hdr)
			return err
		}
		hdr.Method = zip.Deflate
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, f)
		f.Close()
		if err != nil {
			return err
		}
		count++
		return nil
	})
	if walkErr != nil {
		zw.Close()
		out.Close()
		return walkErr
	}
	if err := zw.Close(); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	st, _ := os.Stat(outPath)
	fmt.Printf("%s ZIP dibuat: %s (%s, %d berkas) — bisa dibuka tanpa zulip di OS apa pun\n",
		okCol("✓"), outPath, humanSize(st.Size()), count)
	return nil
}
