package main

// SFX: file keluaran = [binary zulip ini][arsip .zynx][trailer 16 byte:
// u64 offset arsip + magic]. Menjalankan file SFX tanpa argumen akan
// mengekstrak arsip di dalamnya ke folder saat ini; perintah zulip biasa
// (l/t/x) juga bisa membukanya lewat deteksi trailer di openSource.

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// sfxStubBytes memilih biner stub untuk SFX: zulip-stub.exe (khusus
// ekstrak, ~32% lebih kecil) bila ada di samping executable ini,
// kalau tidak pakai executable ini sendiri.
func sfxStubBytes() ([]byte, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if data, err := os.ReadFile(filepath.Join(filepath.Dir(self), "zulip-stub.exe")); err == nil && len(data) > 0 {
		return data, nil
	}
	return os.ReadFile(self)
}

func wrapSFX(tmpArchive, outPath string) error {
	stub, err := sfxStubBytes()
	if err != nil {
		return err
	}
	arc, err := os.Open(tmpArchive)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	if _, err := out.Write(stub); err != nil {
		out.Close()
		return err
	}
	if _, err := io.Copy(out, arc); err != nil {
		arc.Close()
		out.Close()
		return err
	}
	// Tutup SEKARANG, bukan defer: Windows menolak menghapus berkas
	// yang masih terbuka (sharing violation) — tertangkap uji Wine.
	arc.Close()
	var trailer [16]byte
	binary.LittleEndian.PutUint64(trailer[0:8], uint64(len(stub)))
	copy(trailer[8:], sfxTrailerMagic)
	if _, err := out.Write(trailer[:]); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(tmpArchive)
}

// maybeSelfExtract: bila binary yang berjalan adalah SFX dan dipanggil
// tanpa argumen, ekstrak arsip di dalamnya ke folder saat ini.
func maybeSelfExtract() (bool, error) {
	self, err := os.Executable()
	if err != nil {
		return false, nil
	}
	f, err := os.Open(self)
	if err != nil {
		return false, nil
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || st.Size() < 16 {
		return false, nil
	}
	tail := make([]byte, 16)
	if _, err := f.ReadAt(tail, st.Size()-16); err != nil {
		return false, nil
	}
	isSFX := false
	for i, b := range sfxTrailerMagic {
		if tail[8+i] != b {
			break
		}
		if i == len(sfxTrailerMagic)-1 {
			isSFX = true
		}
	}
	if !isSFX {
		return false, nil
	}
	fmt.Println("SFX zulip: mengekstrak arsip di dalam file ini ke folder saat ini...")
	if err := cmdExtract(self, ".", os.Getenv("ZYNX_PASSWORD")); err != nil {
		return true, err
	}
	return true, nil
}
