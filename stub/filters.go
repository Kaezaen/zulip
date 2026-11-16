package main

// Filter pra-proses (diterapkan pada stream solid grup SEBELUM codec).
// Semua filter di sini reversibel secara eksak dan diverifikasi per grup
// sebelum arsip ditulis (lihat encodedGroup.verify di write.go).

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// ---------- Delta ----------
// out[i] = in[i] - in[i-stride] (in[<0] = 0). Menang pada data berstride
// teratur: audio PCM, BMP, tabel numerik, float array.

func deltaEncode(data []byte, stride int) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		var prev byte
		if i >= stride {
			prev = data[i-stride]
		}
		out[i] = b - prev
	}
	return out
}

func deltaDecode(data []byte, stride int) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		var prev byte
		if i >= stride {
			prev = out[i-stride]
		}
		out[i] = b + prev
	}
	return out
}

// ---------- BCJ2 versi kita ----------
// Stream target CALL (E8), JMP (E9), dan Jcc (0F 8x) dipisahkan dari stream
// kode utama; operand relatif diubah ke absolut di stream sampingnya.
// Stream kode jadi bersih dari byte alamat entropi-tinggi, dan stream alamat
// isinya nilai-nilai mirip yang sangat terkompresi.
// Format: [uvarint rawLen][uvarint callLen][uvarint jumpLen][main][call][jump]

func bcj2Encode(data []byte) []byte {
	var main, call, jump bytes.Buffer
	n := len(data)
	for i := 0; i < n; {
		b := data[i]
		switch {
		case (b == 0xE8 || b == 0xE9) && i+5 <= n:
			main.WriteByte(b)
			abs := binary.LittleEndian.Uint32(data[i+1:i+5]) + uint32(i) + 5
			var tmp [4]byte
			binary.LittleEndian.PutUint32(tmp[:], abs)
			if b == 0xE8 {
				call.Write(tmp[:])
			} else {
				jump.Write(tmp[:])
			}
			i += 5
		case b == 0x0F && i+6 <= n && data[i+1] >= 0x80 && data[i+1] <= 0x8F:
			main.WriteByte(0x0F)
			main.WriteByte(data[i+1])
			abs := binary.LittleEndian.Uint32(data[i+2:i+6]) + uint32(i) + 6
			var tmp [4]byte
			binary.LittleEndian.PutUint32(tmp[:], abs)
			jump.Write(tmp[:])
			i += 6
		default:
			main.WriteByte(b)
			i++
		}
	}
	var out bytes.Buffer
	var tmp [binary.MaxVarintLen64]byte
	for _, v := range []uint64{uint64(n), uint64(call.Len()), uint64(jump.Len())} {
		m := binary.PutUvarint(tmp[:], v)
		out.Write(tmp[:m])
	}
	out.Write(main.Bytes())
	out.Write(call.Bytes())
	out.Write(jump.Bytes())
	return out.Bytes()
}

func bcj2Decode(data []byte) ([]byte, error) {
	r := bytes.NewReader(data)
	rawLen, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	callLen, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	jumpLen, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	rest := make([]byte, r.Len())
	if _, err := r.Read(rest); err != nil {
		return nil, err
	}
	mainLen := uint64(len(rest)) - callLen - jumpLen
	if int64(mainLen) < 0 {
		return nil, errors.New("bcj2: panjang stream tidak konsisten")
	}
	mainB := rest[:mainLen]
	callB := rest[mainLen : mainLen+callLen]
	jumpB := rest[mainLen+callLen:]
	out := make([]byte, 0, rawLen)
	ci, ji := 0, 0
	for mi := 0; mi < len(mainB); {
		b := mainB[mi]
		// Aturan ekor: encoder hanya mengonversi opcode bila instruksi utuh
		// muat di sisa input. Sisa output == sisa input (bijeksi), jadi opcode
		// di ekor < 5/6 byte terakhir pasti literal — tanpa aturan ini opcode
		// literal di ujung stream akan salah dibaca sebagai konversi.
		remain := int(rawLen) - len(out)
		switch {
		case (b == 0xE8 || b == 0xE9) && remain >= 5:
			src := callB
			if b == 0xE9 {
				src = jumpB
			}
			idx := &ci
			if b == 0xE9 {
				idx = &ji
			}
			if *idx+4 > len(src) {
				return nil, errors.New("bcj2: stream samping habis")
			}
			abs := binary.LittleEndian.Uint32(src[*idx : *idx+4])
			*idx += 4
			rel := abs - uint32(len(out)) - 5
			out = append(out, b)
			var tmp [4]byte
			binary.LittleEndian.PutUint32(tmp[:], rel)
			out = append(out, tmp[:]...)
			mi++
		case b == 0x0F && remain >= 6 && mi+1 < len(mainB) && mainB[mi+1] >= 0x80 && mainB[mi+1] <= 0x8F:
			if ji+4 > len(jumpB) {
				return nil, errors.New("bcj2: stream jump habis")
			}
			abs := binary.LittleEndian.Uint32(jumpB[ji : ji+4])
			ji += 4
			rel := abs - uint32(len(out)) - 6
			out = append(out, 0x0F, mainB[mi+1])
			var tmp [4]byte
			binary.LittleEndian.PutUint32(tmp[:], rel)
			out = append(out, tmp[:]...)
			mi += 2
		default:
			out = append(out, b)
			mi++
		}
	}
	if uint64(len(out)) != rawLen || ci != len(callB) || ji != len(jumpB) {
		return nil, errors.New("bcj2: hasil decode tidak konsisten")
	}
	return out, nil
}

// ---------- REP-lite ----------
// Preprocessor pencari pengulangan jarak jauh ala REP/SREP FreeArc:
// token stream LZ dengan jendela = SELURUH grup dan match minimum besar (64),
// sehingga hanya pengulangan jauh/substansial yang diganti referensi.
// Codec utama kemudian bekerja di atas token stream ini.
// Format token: 0x00 [uvarint len][literal...] | 0x01 [uvarint dist][uvarint len]

const repMinMatch = 64

func repEncode(data []byte) []byte {
	n := len(data)
	var out bytes.Buffer
	var tmp [binary.MaxVarintLen64]byte
	putU := func(v uint64) {
		m := binary.PutUvarint(tmp[:], v)
		out.Write(tmp[:m])
	}
	if n < repMinMatch {
		out.WriteByte(0)
		putU(uint64(n))
		out.Write(data)
		return out.Bytes()
	}
	table := map[uint32][]int{}
	addPos := func(p int) {
		if p+4 > n {
			return
		}
		k := binary.LittleEndian.Uint32(data[p : p+4])
		lst := table[k]
		if len(lst) >= 4 {
			lst = lst[len(lst)-3:]
		}
		table[k] = append(lst, p)
	}
	matchLen := func(p, i int) int {
		l := 0
		for i+l < n && data[p+l] == data[i+l] {
			l++
		}
		return l
	}
	litStart := 0
	i := 0
	flushLit := func(until int) {
		if until > litStart {
			out.WriteByte(0)
			putU(uint64(until - litStart))
			out.Write(data[litStart:until])
		}
	}
	for i+repMinMatch <= n {
		k := binary.LittleEndian.Uint32(data[i : i+4])
		bestLen, bestPos := 0, -1
		for _, p := range table[k] {
			if p >= i {
				continue
			}
			if l := matchLen(p, i); l > bestLen {
				bestLen, bestPos = l, p
			}
		}
		if bestLen >= repMinMatch {
			flushLit(i)
			out.WriteByte(1)
			putU(uint64(i - bestPos))
			putU(uint64(bestLen))
			for j := i; j < i+bestLen; j += 16 {
				addPos(j)
			}
			i += bestLen
			litStart = i
			continue
		}
		addPos(i)
		i++
	}
	flushLit(n)
	return out.Bytes()
}

func repDecode(data []byte) ([]byte, error) {
	r := bytes.NewReader(data)
	var out []byte
	for r.Len() > 0 {
		tag, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch tag {
		case 0:
			l, err := binary.ReadUvarint(r)
			if err != nil {
				return nil, err
			}
			if uint64(r.Len()) < l {
				return nil, errors.New("rep: literal keluar batas")
			}
			start := len(out)
			out = append(out, make([]byte, l)...)
			if _, err := r.Read(out[start:]); err != nil {
				return nil, err
			}
		case 1:
			dist, err := binary.ReadUvarint(r)
			if err != nil {
				return nil, err
			}
			l, err := binary.ReadUvarint(r)
			if err != nil {
				return nil, err
			}
			if dist == 0 || dist > uint64(len(out)) {
				return nil, errors.New("rep: dist tidak valid")
			}
			for k := uint64(0); k < l; k++ {
				out = append(out, out[len(out)-int(dist)])
			}
		default:
			return nil, errors.New("rep: tag tidak dikenal")
		}
	}
	return out, nil
}

// ---------- dispatch filter ----------

func applyFilter(filter byte, stride int, data []byte, encode bool) ([]byte, error) {
	switch filter {
	case filterNone:
		return data, nil
	case filterBCJ:
		if encode {
			return bcjEncode(data), nil
		}
		return bcjDecode(data), nil
	case filterDelta:
		if stride <= 0 {
			return nil, errors.New("delta: stride tidak valid")
		}
		if encode {
			return deltaEncode(data, stride), nil
		}
		return deltaDecode(data, stride), nil
	case filterBCJ2:
		if encode {
			return bcj2Encode(data), nil
		}
		return bcj2Decode(data)
	case filterREP:
		if encode {
			return repEncode(data), nil
		}
		return repDecode(data)
	}
	return nil, errUnknownCodec
}
