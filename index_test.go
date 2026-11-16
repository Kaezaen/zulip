package main

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func fakeHash(b byte) string {
	h := sha256.Sum256([]byte{b})
	return hex.EncodeToString(h[:])
}

// Index v5: grup membawa metadata blok; entri seperti v4 — urutan wajib
// dir -> fisik (grup, offset) -> ref, kompresi prefix nama, delta
// waktu/grup/offset, hash hanya untuk fisik.
func TestIndexV4Roundtrip(t *testing.T) {
	idx := &Index{Version: 5, Mode: "ultra"}
	idx.Groups = []Group{
		{ID: 0, Key: ".md", Codec: codecZstd, FileOffset: 9, RawSize: 300, CompSize: 100,
			Blocks: []BlockMeta{{Codec: codecZstd, RawSize: 300, CompSize: 100}}},
		{ID: 1, Key: ".pe", Codec: codecBrotli, Filter: filterDelta, Stride: 2, FileOffset: 200, RawSize: 500, CompSize: 200, DictUsed: true,
			Blocks: []BlockMeta{{Codec: codecBrotli, Filter: filterDelta, Stride: 2, RawSize: 500, CompSize: 200, DictUsed: true}}},
	}
	idx.Entries = []Entry{
		{Name: "root", Dir: true, Group: -1, Ref: -1, SHA256: zeroHashHex},
		{Name: "root/a.md", Size: 100, Mode: 0o644, ModUnix: 1000, SHA256: fakeHash(1), Group: 0, Offset: 0, Ref: -1},
		{Name: "root/b.md", Size: 200, Mode: 0o644, ModUnix: 2500, SHA256: fakeHash(2), Group: 0, Offset: 100, Ref: -1},
		{Name: "root/x.exe", Size: 500, Mode: 0o755, ModUnix: 2600, SHA256: fakeHash(3), Group: 1, Offset: 0, Ref: -1},
		{Name: "root/copy.md", Size: 100, Mode: 0o600, ModUnix: 9000, SHA256: fakeHash(1), Group: -1, Ref: 1},
	}
	back, err := unmarshalIndexBinary(idx.marshalBinary())
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Groups) != 2 || len(back.Entries) != 5 {
		t.Fatalf("jumlah berubah: grup=%d entri=%d", len(back.Groups), len(back.Entries))
	}
	g := back.Groups[1]
	if g.Filter != filterDelta || g.Stride != 2 || !g.DictUsed || g.RawSize != 500 {
		t.Fatalf("grup 1 rusak: %+v", g)
	}
	if len(back.Groups[0].Blocks) != 1 || len(g.Blocks) != 1 ||
		g.Blocks[0].Codec != codecBrotli || g.Blocks[0].CompSize != 200 || !g.Blocks[0].DictUsed {
		t.Fatalf("blok grup rusak: %+v / %+v", back.Groups[0].Blocks, g.Blocks)
	}
	for i, want := range idx.Entries {
		got := back.Entries[i]
		if got.Name != want.Name || got.Size != want.Size || got.Mode != want.Mode ||
			got.ModUnix != want.ModUnix || got.SHA256 != want.SHA256 ||
			got.Group != want.Group || got.Offset != want.Offset ||
			got.Ref != want.Ref || got.Dir != want.Dir {
			t.Fatalf("entri %d beda:\n mau %+v\n dapat %+v", i, want, got)
		}
	}
}
