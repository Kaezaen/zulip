package main

// Penulis multi-volume: aliran byte arsip logis yang sama dengan mode
// file-tunggal, dipotong menjadi file <arsip>.001, .002, ... yang masing-
// masing diawali header tetap 32 byte. Ukuran volume adalah batas ukuran
// FILE per volume (header termasuk).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type volumeWriter struct {
	base    string
	maxFile int64
	idx     int
	f       *os.File
	payload int64 // payload tertulis di volume berjalan
	total   int64 // total payload semua volume
	files   []string
}

func newVolumeWriter(base string, maxFile int64) (*volumeWriter, error) {
	if maxFile < volumeHeaderSize+4096 {
		return nil, errors.New("ukuran volume terlalu kecil (minimum 4 KB + header)")
	}
	v := &volumeWriter{base: base, maxFile: maxFile}
	if err := v.openNext(); err != nil {
		return nil, err
	}
	return v, nil
}

func (v *volumeWriter) openNext() error {
	v.idx++
	name := volumePath(v.base, v.idx)
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	hdr := make([]byte, volumeHeaderSize)
	copy(hdr, volumeMagic)
	binary.LittleEndian.PutUint64(hdr[8:16], uint64(v.idx))
	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return err
	}
	v.f = f
	v.payload = 0
	v.files = append(v.files, name)
	return nil
}

func (v *volumeWriter) closeCurrent() error {
	if v.f == nil {
		return nil
	}
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], uint64(v.payload))
	if _, err := v.f.WriteAt(b[:], 16); err != nil {
		return err
	}
	err := v.f.Close()
	v.f = nil
	return err
}

func (v *volumeWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		space := v.maxFile - volumeHeaderSize - v.payload
		if space == 0 {
			if err := v.closeCurrent(); err != nil {
				return written, err
			}
			if err := v.openNext(); err != nil {
				return written, err
			}
			space = v.maxFile - volumeHeaderSize
		}
		n := int64(len(p))
		if n > space {
			n = space
		}
		if _, err := v.f.Write(p[:n]); err != nil {
			return written, err
		}
		v.payload += n
		v.total += n
		written += int(n)
		p = p[n:]
	}
	return written, nil
}

func (v *volumeWriter) Close() error { return v.closeCurrent() }

// parseSize menerima "1048576", "500k", "10m", "2g" (basis 1024).
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return 0, errors.New("ukuran kosong")
	}
	mult := int64(1)
	switch s[len(s)-1] {
	case 'k':
		mult = 1 << 10
	case 'm':
		mult = 1 << 20
	case 'g':
		mult = 1 << 30
	}
	if mult != 1 {
		s = s[:len(s)-1]
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("ukuran tidak valid: %q", s)
	}
	return n * mult, nil
}

// countingWriter menghitung byte logis yang ditulis melaluinya.
type countingWriter struct {
	w interface{ Write([]byte) (int, error) }
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
