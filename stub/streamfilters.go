package main

// Decoder filter versi streaming untuk proses ekstrak/test: grup berfilter
// Delta dan BCJ tidak lagi harus didecode utuh ke RAM.
// BCJ2 dan REP tetap memakai jalur buffered (readGroupFull): BCJ2 menyimpan
// stream samping SETELAH stream utama sehingga penggabungan butuh akses
// acak, dan REP menyalin dari riwayat sejauh grup penuh.

import (
	"encoding/binary"
	"io"
)

// ---------- delta ----------

type deltaStreamReader struct {
	inner  io.Reader
	stride int
	win    []byte // jendela sirkular output: slot q%stride = output[q-stride..]
	pos    int64  // posisi output absolut dari byte berikutnya yang diproses
	buf    []byte
	off    int
	err    error
}

func newDeltaStreamReader(inner io.Reader, stride int) *deltaStreamReader {
	return &deltaStreamReader{inner: inner, stride: stride, win: make([]byte, stride)}
}

func (r *deltaStreamReader) Read(p []byte) (int, error) {
	if r.off >= len(r.buf) {
		if r.err != nil {
			return 0, r.err
		}
		tmp := make([]byte, 32<<10)
		n, err := r.inner.Read(tmp)
		tmp = tmp[:n]
		for i, b := range tmp {
			slot := int((r.pos + int64(i)) % int64(r.stride))
			var prev byte
			if r.pos+int64(i) >= int64(r.stride) {
				prev = r.win[slot]
			}
			v := b + prev
			r.win[slot] = v
			tmp[i] = v
		}
		r.pos += int64(n)
		r.buf, r.off = tmp, 0
		if err != nil {
			r.err = err
			if n == 0 {
				return 0, err
			}
		}
	}
	n := copy(p, r.buf[r.off:])
	r.off += n
	return n, nil
}

// ---------- BCJ (decode: absolut -> relatif) ----------

type bcjStreamReader struct {
	inner io.Reader
	buf   []byte // input belum diproses; buf[0] ada di posisi pos
	pos   int64
	out   []byte
	off   int
	eof   bool
	err   error
}

func newBCJStreamReader(inner io.Reader) *bcjStreamReader {
	return &bcjStreamReader{inner: inner}
}

func (r *bcjStreamReader) process(final bool) {
	i := 0
	for i < len(r.buf) {
		if i+5 > len(r.buf) {
			if !final {
				break // belum bisa memutuskan opcode di tepi buffer
			}
			i = len(r.buf) // ekor < 5 byte: lolos apa adanya
			break
		}
		b := r.buf[i]
		if b == 0xE8 || b == 0xE9 {
			v := binary.LittleEndian.Uint32(r.buf[i+1:i+5]) - uint32(r.pos) - uint32(i) - 5
			binary.LittleEndian.PutUint32(r.buf[i+1:i+5], v)
			i += 5
		} else {
			i++
		}
	}
	r.out = append(r.out[:0], r.buf[:i]...)
	r.off = 0
	r.pos += int64(i)
	r.buf = append(r.buf[:0], r.buf[i:]...)
}

func (r *bcjStreamReader) Read(p []byte) (int, error) {
	for r.off >= len(r.out) {
		if r.err != nil {
			return 0, r.err
		}
		if !r.eof {
			tmp := make([]byte, 32<<10)
			n, err := r.inner.Read(tmp)
			r.buf = append(r.buf, tmp[:n]...)
			if err == io.EOF {
				r.eof = true
			} else if err != nil {
				r.err = err
				return 0, err
			}
		}
		r.process(r.eof)
		if len(r.out) == 0 {
			if r.eof {
				r.err = io.EOF
				return 0, io.EOF
			}
			// buffer belum cukup untuk satu keputusan pun; baca lagi
		}
	}
	n := copy(p, r.out[r.off:])
	r.off += n
	return n, nil
}

// wrapFilterStream membungkus reader codec dengan decoder filter streaming
// bila tersedia; ok=false berarti pemanggil harus memakai jalur buffered.
func wrapFilterStream(inner io.Reader, g Group) (io.Reader, bool) {
	switch g.Filter {
	case filterDelta:
		if g.Stride <= 0 {
			return nil, false
		}
		return newDeltaStreamReader(inner, g.Stride), true
	case filterBCJ:
		return newBCJStreamReader(inner), true
	}
	return nil, false
}
