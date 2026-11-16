package main

import (
	"bytes"
	"io"
	"math/rand"
	"testing"
)

// dripReader mengembalikan paling banyak n byte per Read — kondisi
// perbatasan terburuk untuk decoder streaming.
type dripReader struct {
	data []byte
	n    int
}

func (d *dripReader) Read(p []byte) (int, error) {
	if len(d.data) == 0 {
		return 0, io.EOF
	}
	k := d.n
	if k > len(d.data) {
		k = len(d.data)
	}
	if k > len(p) {
		k = len(p)
	}
	copy(p, d.data[:k])
	d.data = d.data[k:]
	return k, nil
}

func TestDeltaStreamEqualsBuffered(t *testing.T) {
	rng := rand.New(rand.NewSource(9))
	data := make([]byte, 100003)
	for i := range data {
		data[i] = byte(i/11 + rng.Intn(5))
	}
	for _, s := range []int{1, 2, 4, 16} {
		enc := deltaEncode(data, s)
		want := deltaDecode(enc, s)
		for _, drip := range []int{1, 3, 7, 4096} {
			got, err := io.ReadAll(newDeltaStreamReader(&dripReader{data: enc, n: drip}, s))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) || !bytes.Equal(got, data) {
				t.Fatalf("delta stream stride=%d drip=%d tidak sama", s, drip)
			}
		}
	}
}

func TestBCJStreamEqualsBuffered(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	var data []byte
	for len(data) < 150001 {
		switch rng.Intn(4) {
		case 0:
			data = append(data, 0xE8, 0x78, 0x56, 0x34, 0x12)
		case 1:
			data = append(data, 0xE9, 0x00, 0x00, 0x00, 0x80)
		default:
			data = append(data, byte(rng.Intn(256)))
		}
	}
	data = append(data, 0xE8, 0x01) // ekor ganjil
	enc := bcjEncode(data)
	want := bcjDecode(enc)
	if !bytes.Equal(want, data) {
		t.Fatal("bcj buffered saja tidak reversibel pada data uji")
	}
	for _, drip := range []int{1, 2, 5, 8192} {
		got, err := io.ReadAll(newBCJStreamReader(&dripReader{data: enc, n: drip}))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, data) {
			t.Fatalf("bcj stream drip=%d tidak sama", drip)
		}
	}
}
