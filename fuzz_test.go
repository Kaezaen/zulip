package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Fuzz parser index biner: input apa pun tidak boleh panic.
func FuzzUnmarshalIndex(f *testing.F) {
	idx := &Index{Version: 5, Mode: "normal"}
	idx.Groups = []Group{{ID: 0, Key: ".md", FileOffset: 9, RawSize: 10, CompSize: 5,
		Blocks: []BlockMeta{{Codec: codecZstd, RawSize: 10, CompSize: 5}}}}
	idx.Entries = []Entry{
		{Name: "d", Dir: true, Group: -1, Ref: -1, SHA256: zeroHashHex},
		{Name: "d/a.md", Size: 10, Mode: 0o644, ModUnix: 5, SHA256: zeroHashHex, Group: 0, Ref: -1},
	}
	f.Add(idx.marshalBinary())
	f.Add([]byte{3, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = unmarshalIndexBinary(data)
	})
}

// Fuzz jalur buka arsip penuh pada file sementara.
func FuzzOpenArchive(f *testing.F) {
	dir := f.TempDir()
	arc := filepath.Join(dir, "seed.zynx")
	if err := cmdAdd("normal", arc, []string{"testdata/dup"}, addOptions{}); err == nil {
		if b, err := os.ReadFile(arc); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte("ZYNX\x1a\x05\x00\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		p := filepath.Join(t.TempDir(), "x.zynx")
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		_ = cmdTest(p, "")
	})
}
