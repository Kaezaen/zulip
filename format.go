package main

// Format .zynx v5 (zulip) — clean-room, bukan turunan RAR:
//
//	[8 byte magic "ZYNX\x1a\x05\x00\x00"]
//	[1 byte flags: bit0 = terenkripsi]
//	bila terenkripsi: [16 byte salt][uvarint argonTime][uvarint argonMemKiB][uvarint argonThreads]
//	[Group 0][Group 1]...[Group N]
//	  polos:      Group = [uvarint dictLen][dict bytes][compressed solid stream]
//	  terenkripsi: Group = [uvarint cipherLen][12 nonce][AES-256-GCM(segment polos di atas)]
//	  Solid stream = gabungan isi semua file dalam grup (urut sesuai index)
//	[Segmen index: 1 byte flag (0=mentah, 1=zstd) + index biner;
//	 bila terenkripsi seluruh data setelah flag adalah seal(index)]
//	[Footer 16 byte: int64 LE offset index + "ZYNX\x1aEND"]
//
// Enkripsi: AES-256-GCM per grup + index (nama file tersembunyi),
// kunci Argon2id(password, salt). Arsip terenkripsi selalu dibaca utuh
// per grup (tidak streaming) — tag GCM harus diverifikasi sebelum pakai.
//
// Format v5: grup dipecah menjadi blok-blok solid independen (maks
// 32 MB mentah, metadata per blok di index v5); segmen grup =
// [chunk dictionary bila ada][blok...], per chunk bila terenkripsi
// [uvarint len][sealed AES-GCM], bila tidak byte codec mentah. Ini
// membatasi RAM penulis & pembaca sekitar satu blok (hardening v0.5).
// Index biner v5 mewarisi skema entri v4: entri diurutkan dir -> fisik per (grup, offset) -> ref;
// nama dikompresi prefix, waktu/grup/offset delta berantai, hash SHA-256
// hanya disimpan untuk entri fisik (dir & ref tidak).
// Opsi penulisan lain (lihat recovery.go, volume.go, sfx.go): segmen
// recovery Reed-Solomon setelah footer, pemecahan multi-volume dengan
// header 32 byte per volume, dan pembungkus SFX (stub + trailer).
//
// Kompatibilitas mundur: reader menerima .zynx v4/v3/v2 (magic
// \x04/\x03/\x02, index biner v4/v3/v2) dan .adit v0.1 (index JSON).

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
)

var (
	magicHeader   = []byte{'Z', 'Y', 'N', 'X', 0x1a, 0x05, 0x00, 0x00} // v5 (tulis)
	magicHeaderV4 = []byte{'Z', 'Y', 'N', 'X', 0x1a, 0x04, 0x00, 0x00} // v4 (baca)
	magicHeaderV3 = []byte{'Z', 'Y', 'N', 'X', 0x1a, 0x03, 0x00, 0x00} // v3 (baca)
	magicHeaderV2 = []byte{'Z', 'Y', 'N', 'X', 0x1a, 0x02, 0x00, 0x00} // v2 (baca)
	magicFooter   = []byte{'Z', 'Y', 'N', 'X', 0x1a, 'E', 'N', 'D'}
	magicHeaderV1 = []byte{'A', 'D', 'I', 'T', 0x1a, 0x01, 0x00, 0x00}
	magicFooterV1 = []byte{'A', 'D', 'I', 'T', 0x1a, 'E', 'N', 'D'}
)

const (
	codecStore  byte = 0
	codecZstd   byte = 1
	codecLZMA2  byte = 2
	codecBrotli byte = 3
)

const (
	filterNone  byte = 0
	filterBCJ   byte = 1 // x86 CALL/JMP translation, diterapkan sebelum codec
	filterDelta byte = 2 // delta dengan stride (Group.Stride)
	filterBCJ2  byte = 3 // stream E8/E9/Jcc terpisah dari stream kode
	filterREP   byte = 4 // token copy jarak jauh (REP-lite)
)

func codecName(c byte) string {
	switch c {
	case codecStore:
		return "store"
	case codecZstd:
		return "zstd"
	case codecLZMA2:
		return "lzma2"
	case codecBrotli:
		return "brotli"
	}
	return "?"
}

const zeroHashHex = "0000000000000000000000000000000000000000000000000000000000000000"

type Entry struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    uint32 `json:"mode"`
	ModUnix int64  `json:"mod_unix_nano"`
	SHA256  string `json:"sha256"`
	Group   int    `json:"group"`
	Offset  int64  `json:"offset"`
	Ref     int    `json:"ref"`
	Dir     bool   `json:"dir,omitempty"`
}

// BlockMeta: satu blok solid di dalam grup (v5). Grup besar dipecah
// menjadi blok-blok independen (maks ~32 MB mentah) agar RAM terbatas.
type BlockMeta struct {
	Codec    byte  `json:"codec"`
	Filter   byte  `json:"filter"`
	Stride   int   `json:"stride"`
	RawSize  int64 `json:"raw_size"`
	CompSize int64 `json:"comp_size"`
	DictUsed bool  `json:"dict_used,omitempty"`
}

type Group struct {
	Blocks     []BlockMeta `json:"blocks,omitempty"`
	ID         int         `json:"id"`
	Key        string      `json:"key"`
	Codec      byte        `json:"codec"`
	Filter     byte        `json:"filter,omitempty"`
	Stride     int         `json:"stride,omitempty"`
	FileOffset int64       `json:"file_offset"`
	RawSize    int64       `json:"raw_size"`
	CompSize   int64       `json:"comp_size"`
	DictSize   int         `json:"dict_size"`
	DictUsed   bool        `json:"dict_used,omitempty"`
}

type Index struct {
	Recovery *recoveryInfo `json:"-"` // runtime saja: terisi bila arsip punya recovery record
	Version  int           `json:"version"`
	Mode     string        `json:"mode"`
	Groups   []Group       `json:"groups"`
	Entries  []Entry       `json:"entries"`
}

// ---------- index v1 (JSON, hanya untuk membaca arsip lama) ----------

func unmarshalIndexJSON(b []byte) (*Index, error) {
	var idx Index
	err := json.Unmarshal(b, &idx)
	return &idx, err
}

// ---------- index v2 (biner) ----------

type binWriter struct{ buf bytes.Buffer }

func (w *binWriter) uvarint(v uint64) {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	w.buf.Write(tmp[:n])
}
func (w *binWriter) varint(v int64) {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutVarint(tmp[:], v)
	w.buf.Write(tmp[:n])
}
func (w *binWriter) str(s string) { w.uvarint(uint64(len(s))); w.buf.WriteString(s) }
func (w *binWriter) byte_(b byte) { w.buf.WriteByte(b) }

func (idx *Index) marshalBinary() []byte {
	w := &binWriter{}
	w.uvarint(5)
	w.str(idx.Mode)
	w.uvarint(uint64(len(idx.Groups)))
	for _, g := range idx.Groups {
		w.uvarint(uint64(g.ID))
		w.str(g.Key)
		w.varint(g.FileOffset)
		w.varint(g.RawSize)
		w.varint(g.CompSize)
		w.uvarint(uint64(g.DictSize))
		if g.DictUsed {
			w.byte_(1)
		} else {
			w.byte_(0)
		}
		w.uvarint(uint64(len(g.Blocks)))
		for _, b := range g.Blocks {
			w.byte_(b.Codec)
			w.byte_(b.Filter)
			w.byte_(byte(b.Stride))
			w.varint(b.RawSize)
			w.varint(b.CompSize)
			if b.DictUsed {
				w.byte_(1)
			} else {
				w.byte_(0)
			}
		}
	}
	// Entri v4 (urutan wajib: dir, lalu fisik per (grup,offset), lalu ref —
	// diatur pemanggil): nama dikompresi prefix terhadap entri sebelumnya,
	// waktu delta berantai, grup/offset delta, hash hanya untuk entri fisik.
	w.uvarint(uint64(len(idx.Entries)))
	prevName := ""
	var lastMod int64
	lastGroup, lastOffset := 0, int64(0)
	for _, e := range idx.Entries {
		var flags byte
		if e.Dir {
			flags |= 1
		}
		if e.Ref >= 0 {
			flags |= 2
		}
		w.byte_(flags)
		p := 0
		for p < len(prevName) && p < len(e.Name) && prevName[p] == e.Name[p] {
			p++
		}
		w.uvarint(uint64(p))
		w.str(e.Name[p:])
		prevName = e.Name
		if e.Dir {
			continue
		}
		w.uvarint(uint64(e.Mode))
		w.varint(e.ModUnix - lastMod)
		lastMod = e.ModUnix
		if e.Ref >= 0 {
			w.uvarint(uint64(e.Ref))
			continue
		}
		w.varint(e.Size)
		hb, _ := hex.DecodeString(e.SHA256)
		if len(hb) != 32 {
			hb = make([]byte, 32)
		}
		w.buf.Write(hb)
		w.uvarint(uint64(e.Group - lastGroup))
		if e.Group != lastGroup {
			lastOffset = 0
		}
		w.varint(e.Offset - lastOffset)
		lastOffset = e.Offset
		lastGroup = e.Group
	}
	return w.buf.Bytes()
}

type binReader struct {
	r   *bytes.Reader
	err error
}

func (rd *binReader) uvarint() uint64 {
	if rd.err != nil {
		return 0
	}
	v, err := binary.ReadUvarint(rd.r)
	if err != nil {
		rd.err = err
	}
	return v
}
func (rd *binReader) varint() int64 {
	if rd.err != nil {
		return 0
	}
	v, err := binary.ReadVarint(rd.r)
	if err != nil {
		rd.err = err
	}
	return v
}
func (rd *binReader) str() string {
	n := rd.uvarint()
	if rd.err != nil || n > 1<<24 {
		if rd.err == nil {
			rd.err = errors.New("string index terlalu panjang")
		}
		return ""
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rd.r, b); err != nil {
		rd.err = err
	}
	return string(b)
}
func (rd *binReader) byte_() byte {
	if rd.err != nil {
		return 0
	}
	b, err := rd.r.ReadByte()
	if err != nil {
		rd.err = err
	}
	return b
}

func unmarshalIndexBinary(b []byte) (*Index, error) {
	rd := &binReader{r: bytes.NewReader(b)}
	ver := rd.uvarint()
	if ver != 2 && ver != 3 && ver != 4 && ver != 5 {
		return nil, errors.New("versi index biner tidak dikenal")
	}
	idx := &Index{Version: int(ver)}
	idx.Mode = rd.str()
	ng := rd.uvarint()
	for i := uint64(0); i < ng && rd.err == nil; i++ {
		var g Group
		g.ID = int(rd.uvarint())
		g.Key = rd.str()
		if ver == 5 {
			g.FileOffset = rd.varint()
			g.RawSize = rd.varint()
			g.CompSize = rd.varint()
			g.DictSize = int(rd.uvarint())
			g.DictUsed = rd.byte_() == 1
			nb := rd.uvarint()
			for j := uint64(0); j < nb && rd.err == nil; j++ {
				var b BlockMeta
				b.Codec = rd.byte_()
				b.Filter = rd.byte_()
				b.Stride = int(rd.byte_())
				b.RawSize = rd.varint()
				b.CompSize = rd.varint()
				b.DictUsed = rd.byte_() == 1
				g.Blocks = append(g.Blocks, b)
			}
			if len(g.Blocks) > 0 {
				g.Codec, g.Filter, g.Stride = g.Blocks[0].Codec, g.Blocks[0].Filter, g.Blocks[0].Stride
			}
			idx.Groups = append(idx.Groups, g)
			continue
		}
		g.Codec = rd.byte_()
		g.Filter = rd.byte_()
		if ver >= 3 {
			g.Stride = int(rd.byte_())
		}
		g.FileOffset = rd.varint()
		g.RawSize = rd.varint()
		g.CompSize = rd.varint()
		g.DictSize = int(rd.uvarint())
		g.DictUsed = rd.byte_() == 1
		idx.Groups = append(idx.Groups, g)
	}
	ne := rd.uvarint()
	if ver == 4 || ver == 5 {
		prevName := ""
		var lastMod int64
		lastGroup, lastOffset := 0, int64(0)
		for i := uint64(0); i < ne && rd.err == nil; i++ {
			var e Entry
			e.Group, e.Ref = -1, -1
			flags := rd.byte_()
			e.Dir = flags&1 != 0
			isRef := flags&2 != 0
			p := rd.uvarint()
			suf := rd.str()
			if int(p) > len(prevName) {
				rd.err = errors.New("prefix nama index rusak")
				break
			}
			e.Name = prevName[:p] + suf
			prevName = e.Name
			if e.Dir {
				e.SHA256 = zeroHashHex
				idx.Entries = append(idx.Entries, e)
				continue
			}
			e.Mode = uint32(rd.uvarint())
			lastMod += rd.varint()
			e.ModUnix = lastMod
			if isRef {
				e.Ref = int(rd.uvarint())
				if e.Ref < 0 || e.Ref >= len(idx.Entries) {
					rd.err = errors.New("ref index rusak")
					break
				}
				src := idx.Entries[e.Ref]
				e.Size = src.Size
				e.SHA256 = src.SHA256
				idx.Entries = append(idx.Entries, e)
				continue
			}
			e.Size = rd.varint()
			hb := make([]byte, 32)
			if _, err := io.ReadFull(rd.r, hb); err != nil {
				rd.err = err
				break
			}
			e.SHA256 = hex.EncodeToString(hb)
			gd := int(rd.uvarint())
			if gd != 0 {
				lastOffset = 0 // grup baru: basis offset mulai dari nol
			}
			lastGroup += gd
			e.Group = lastGroup
			e.Offset = lastOffset + rd.varint()
			lastOffset = e.Offset
			idx.Entries = append(idx.Entries, e)
		}
		if rd.err != nil {
			return nil, rd.err
		}
		return idx, nil
	}
	for i := uint64(0); i < ne && rd.err == nil; i++ {
		var e Entry
		e.Name = rd.str()
		e.Size = rd.varint()
		e.Mode = uint32(rd.uvarint())
		e.ModUnix = rd.varint()
		hb := make([]byte, 32)
		if _, err := io.ReadFull(rd.r, hb); err != nil {
			rd.err = err
			break
		}
		e.SHA256 = hex.EncodeToString(hb)
		e.Group = int(rd.varint())
		e.Offset = rd.varint()
		e.Ref = int(rd.varint())
		e.Dir = rd.byte_() == 1
		idx.Entries = append(idx.Entries, e)
	}
	if rd.err != nil {
		return nil, rd.err
	}
	return idx, nil
}
