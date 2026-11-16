package main

import (
	"bytes"
	"encoding/binary"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz/lzma"
)

// ---------- Zstandard ----------

func zstdEncode(data []byte, level zstd.EncoderLevel, window int, dict []byte) ([]byte, error) {
	opts := []zstd.EOption{zstd.WithEncoderLevel(level), zstd.WithWindowSize(window)}
	if len(dict) > 0 {
		opts = append(opts, zstd.WithEncoderDict(dict))
	}
	enc, err := zstd.NewWriter(nil, opts...)
	if err != nil {
		return nil, err
	}
	return enc.EncodeAll(data, nil), nil
}

func zstdDecode(data []byte, dict []byte, rawSize int64) ([]byte, error) {
	opts := []zstd.DOption{zstd.WithDecoderMaxWindow(1 << 30)}
	if len(dict) > 0 {
		opts = append(opts, zstd.WithDecoderDicts(dict))
	}
	dec, err := zstd.NewReader(nil, opts...)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	out := make([]byte, 0, rawSize)
	return dec.DecodeAll(data, out)
}

// buildDict melatih dictionary zstd dari sampel isi file grup itu sendiri.
// API klauspost: History = isi dictionary (gabungan sampel, maks ~100 KB),
// Contents = sampel untuk optimasi tabel entropi. Tanpa History, BuildDict gagal.
func buildDict(samples [][]byte) (dict []byte, err error) {
	// BuildDict bisa PANIC pada sampel besar/biner ("can only encode up to
	// 64K sequences", terukur pada grup PE folder WinRAR) — pulihkan jadi error.
	defer func() {
		if r := recover(); r != nil {
			dict, err = nil, errUnknownCodec
		}
	}()
	total := 0
	for _, s := range samples {
		total += len(s)
		if len(s) > 256<<10 || total > 4<<20 {
			return nil, errUnknownCodec // dict hanya untuk banyak file kecil
		}
	}
	var hist []byte
	for _, s := range samples {
		hist = append(hist, s...)
		if len(hist) >= 100_000 {
			break
		}
	}
	if len(hist) < 8 {
		return nil, errUnknownCodec
	}
	return zstd.BuildDict(zstd.BuildDictOptions{ID: 1, History: hist, Contents: samples})
}

// ---------- LZMA2 (raw, via ulikunitz/xz lzma) ----------

func lzma2Encode(data []byte, dictCap int) ([]byte, error) {
	if dictCap < lzma.MinDictCap {
		dictCap = lzma.MinDictCap
	}
	// Matcher HashTable4, BUKAN BinaryTree: BT di pustaka ini patologis
	// lambat pada data biner (terukur: >4 menit untuk 4,2 MB, tidak selesai),
	// HashTable4 menyelesaikan grup yang sama dalam ~1 detik dengan hasil
	// yang praktis setara.
	cfg := lzma.Writer2Config{
		DictCap: dictCap,
		Matcher: lzma.HashTable4,
	}
	if err := cfg.Verify(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	w, err := cfg.NewWriter2(&buf)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func lzma2Decode(data []byte) ([]byte, error) {
	cfg := lzma.Reader2Config{DictCap: 1 << 30}
	r, err := cfg.NewReader2(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

// ---------- Brotli ----------

func brotliEncode(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := brotli.NewWriterOptions(&buf, brotli.WriterOptions{Quality: 11})
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func brotliDecode(data []byte) ([]byte, error) {
	return io.ReadAll(brotli.NewReader(bytes.NewReader(data)))
}

// ---------- Filter BCJ x86 ----------
//
// Transformasi reversibel klasik (konsep filter BCJ xz/7-zip, ditulis ulang):
// operand instruksi CALL/JMP relatif (0xE8/0xE9 + int32 LE) diubah dari
// relatif-terhadap-posisi menjadi absolut, dan sebaliknya saat decode.
// Alamat absolut berulang jauh lebih baik untuk kompresor LZ.
// Pemindaian identik di kedua arah (lewati 5 byte setelah opcode) membuat
// transformasi ini eksak terbalikkan, termasuk untuk false positive.

func bcjTransform(src []byte, encode bool) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	for i := 0; i+5 <= len(out); {
		b := out[i]
		if b != 0xE8 && b != 0xE9 {
			i++
			continue
		}
		v := binary.LittleEndian.Uint32(out[i+1 : i+5])
		if encode {
			v += uint32(i) + 5
		} else {
			v -= uint32(i) + 5
		}
		binary.LittleEndian.PutUint32(out[i+1:i+5], v)
		i += 5
	}
	return out
}

func bcjEncode(src []byte) []byte { return bcjTransform(src, true) }
func bcjDecode(src []byte) []byte { return bcjTransform(src, false) }

// ---------- dispatch ----------

func decodeGroup(codec byte, comp, dict []byte, rawSize int64) ([]byte, error) {
	var out []byte
	var err error
	switch codec {
	case codecStore:
		out = make([]byte, len(comp))
		copy(out, comp)
	case codecZstd:
		out, err = zstdDecode(comp, dict, rawSize)
	case codecLZMA2:
		out, err = lzma2Decode(comp)
	case codecBrotli:
		out, err = brotliDecode(comp)
	default:
		return nil, errUnknownCodec
	}
	return out, err
}

func applyFilterDecode(filter byte, stride int, raw []byte) ([]byte, error) {
	return applyFilter(filter, stride, raw, false)
}
