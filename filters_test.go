package main

import (
	"bytes"
	"math/rand"
	"os"
	"testing"
)

func TestDeltaRoundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	data := make([]byte, 100000)
	for i := range data {
		data[i] = byte(i/7 + rng.Intn(3))
	}
	for _, s := range []int{1, 2, 3, 4, 6, 8, 16, 32} {
		if got := deltaDecode(deltaEncode(data, s), s); !bytes.Equal(got, data) {
			t.Fatalf("delta stride %d tidak reversibel", s)
		}
	}
}

func TestBCJ2RoundtripSynthetic(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	var data []byte
	for len(data) < 200000 {
		switch rng.Intn(5) {
		case 0:
			data = append(data, 0xE8, 0x10, 0x00, 0x00, 0x00)
		case 1:
			data = append(data, 0xE9, 0xF0, 0xFF, 0xFF, 0xFF)
		case 2:
			data = append(data, 0x0F, 0x84, 0x20, 0x00, 0x00, 0x00)
		case 3:
			data = append(data, 0x0F, 0x8F, 0x01, 0x02, 0x03, 0x04, 0x90)
		default:
			data = append(data, byte(rng.Intn(256)))
		}
	}
	// potongan di ujung: opcode tanpa operand penuh harus tetap aman
	data = append(data, 0xE8, 0x01, 0x02)
	got, err := bcj2Decode(bcj2Encode(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("bcj2 sintetis tidak reversibel")
	}
}

func TestBCJ2RoundtripRealPE(t *testing.T) {
	data, err := os.ReadFile(os.ExpandEnv("$HOME/workspace/user/files/WinRAR.zip"))
	if err != nil {
		t.Skip("zip contoh tidak ada")
	}
	// pakai isi zip apa adanya sebagai data biner kaya pola E8/E9
	got, err := bcj2Decode(bcj2Encode(data))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("bcj2 data nyata tidak reversibel")
	}
}

func TestREPRoundtrip(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	block := make([]byte, 300000)
	rng.Read(block)
	var data []byte
	data = append(data, block...)
	data = append(data, []byte("--- pemisah unik ---")...)
	// salinan blok yang sama jauh di belakang, dengan sedikit perubahan
	dup := append([]byte{}, block...)
	for i := 0; i < 100; i++ {
		dup[rng.Intn(len(dup))] ^= 0xFF
	}
	data = append(data, dup...)
	enc := repEncode(data)
	dec, err := repDecode(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, data) {
		t.Fatal("rep tidak reversibel")
	}
	if len(enc) >= len(data) {
		t.Fatalf("rep seharusnya menyusutkan data repetitif jauh: %d >= %d", len(enc), len(data))
	}
	t.Logf("rep: %d -> %d token byte", len(data), len(enc))
}

func TestCryptoSealOpen(t *testing.T) {
	cc, salt, err := newWriteCrypto("kata-sandi-uji")
	if err != nil {
		t.Fatal(err)
	}
	if len(salt) != saltLen {
		t.Fatal("salt salah")
	}
	plain := []byte("data rahasia 123")
	sealed, err := cc.seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	back, err := cc.open(sealed)
	if err != nil || !bytes.Equal(back, plain) {
		t.Fatal("seal/open gagal")
	}
	rc := newReadCrypto("kata-sandi-uji", salt, argonTime, argonMemKiB, argonThreads)
	if _, err := rc.open(sealed); err != nil {
		t.Fatal("kunci turunan ulang tidak cocok")
	}
	wrong := newReadCrypto("bukan-itu", salt, argonTime, argonMemKiB, argonThreads)
	if _, err := wrong.open(sealed); err == nil {
		t.Fatal("password salah seharusnya gagal")
	}
	sealed[20] ^= 0xFF
	if _, err := cc.open(sealed); err == nil {
		t.Fatal("data diubah seharusnya gagal tag GCM")
	}
}
