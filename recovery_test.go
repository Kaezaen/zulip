package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryRepairRoundtrip(t *testing.T) {
	dir := t.TempDir()
	arc := filepath.Join(dir, "a.zynx")
	if err := cmdAdd("normal", arc, []string{"testdata/docs"}, addOptions{recoveryPct: 10}); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(arc)
	if err != nil {
		t.Fatal(err)
	}
	// Rusak 2 blok di wilayah data.
	dmg := append([]byte{}, orig...)
	for off := 5000; off < 9000; off++ {
		dmg[off] ^= 0xFF
	}
	if err := os.WriteFile(arc, dmg, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cmdRepair(arc); err != nil {
		t.Fatal(err)
	}
	back, err := os.ReadFile(arc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, orig) {
		t.Fatal("arsip hasil repair tidak identik dengan aslinya")
	}
	// Repair pada arsip sehat harus sukses tanpa mengubah apa pun.
	if err := cmdRepair(arc); err != nil {
		t.Fatal(err)
	}
}
