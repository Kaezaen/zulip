package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func treeHashes(t *testing.T, root string) map[string]string {
	t.Helper()
	m := map[string]string{}
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if fi.IsDir() {
			m[rel+"/"] = "dir"
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		m[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// Kasus tepi: dir kosong bersarang, nama unicode & panjang, file kosong,
// dan file yang melintasi batas blok 32 MB (di tengah file maupun antar file).
func TestEdgeCasesMultiBlock(t *testing.T) {
	src := filepath.Join(t.TempDir(), "src")
	rng := rand.New(rand.NewSource(7))
	pattern := func(n int, seed int64) []byte {
		r := rand.New(rand.NewSource(seed))
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(r.Intn(7)) // sangat terkompresi, cepat
		}
		return b
	}
	writeFile(t, filepath.Join(src, "kosong.txt"), nil)
	writeFile(t, filepath.Join(src, "a", "b", "c", "dalam.md"), []byte("# halo\n"))
	if err := os.MkdirAll(filepath.Join(src, "dir_kosong", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(src, "dokumen_üñïçødé.md"), []byte("isi unicode"))
	writeFile(t, filepath.Join(src, strings.Repeat("panjang", 25)+".md"), pattern(1234, 3))
	writeFile(t, filepath.Join(src, "nol_40mb.bin"), make([]byte, 40<<20))
	writeFile(t, filepath.Join(src, "pola_a.bin"), pattern(20<<20, 11))
	writeFile(t, filepath.Join(src, "pola_b.bin"), pattern(20<<20, 12))
	_ = rng

	arc := filepath.Join(t.TempDir(), "edge.zynx")
	if err := cmdAdd("normal", arc, []string{src}, addOptions{}); err != nil {
		t.Fatal(err)
	}
	// Grup .bin (100 MB) wajib terpecah > 1 blok.
	idx, f, _, err := openArchive(arc, "")
	if err != nil {
		t.Fatal(err)
	}
	multi := false
	for _, g := range idx.Groups {
		if len(g.Blocks) > 1 {
			multi = true
		}
	}
	f.Close()
	if !multi {
		t.Fatal("tidak ada grup multi-blok; pemecahan blok tidak terjadi")
	}
	dst := filepath.Join(t.TempDir(), "out")
	if err := cmdExtract(arc, dst, ""); err != nil {
		t.Fatal(err)
	}
	want := treeHashes(t, src)
	got := treeHashes(t, filepath.Join(dst, "src"))
	// dir kosong tidak tercatat sebagai entri file; bandingkan file saja +
	// keberadaan dir kosong secara eksplisit.
	for k, v := range want {
		if strings.HasSuffix(k, "/") {
			continue
		}
		if got[k] != v {
			t.Fatalf("file %s beda: mau %s dapat %s", k, v, got[k])
		}
	}
	if _, err := os.Stat(filepath.Join(dst, "src", "dir_kosong", "sub")); err != nil {
		t.Fatalf("dir kosong tidak terekstrak: %v", err)
	}
}

// Arsip terpotong/terkorupsi tidak boleh panic — hanya error.
func TestCorruptNeverPanics(t *testing.T) {
	arc := filepath.Join(t.TempDir(), "k.zynx")
	if err := cmdAdd("normal", arc, []string{"testdata/dup"}, addOptions{}); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(arc)
	if err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(t.TempDir(), "c.zynx")
	check := func(data []byte, label string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("PANIC pada %s: %v", label, r)
			}
		}()
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			t.Fatal(err)
		}
		_ = cmdTest(tmp, "")
		_ = cmdList(tmp, "")
	}
	// Semua prefix terpotong (sampling).
	for n := 0; n < len(orig); n += 13 {
		check(orig[:n], "prefix")
	}
	check(orig, "utuh")
	// Korupsi byte acak deterministik.
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 300; i++ {
		d := append([]byte{}, orig...)
		for j := 0; j < 24; j++ {
			d[rng.Intn(len(d))] ^= byte(1 << rng.Intn(8))
		}
		check(d, "korupsi")
	}
	// Byte acak murni.
	for i := 0; i < 20; i++ {
		d := make([]byte, 4096)
		rng.Read(d)
		check(d, "acak")
	}
	// Kepala valid + ekor acak.
	d := append([]byte{}, orig[:64]...)
	tail := make([]byte, 2048)
	rng.Read(tail)
	check(append(d, tail...), "kepala-valid")
	if !bytes.Contains(orig, []byte("ZYNX")) {
		t.Fatal("arsip uji tidak valid")
	}
}
