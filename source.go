package main

// Sumber baca arsip: satu file polos, rangkaian volume (.001, .002, ...),
// atau file SFX (arsip menempel di belakang stub). Ketiganya diekspos
// sebagai satu ruang byte logis [0, Size) yang identik dengan arsip
// file-tunggal, sehingga seluruh kode baca tidak berubah semantiknya.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

type archiveSource interface {
	io.ReaderAt
	io.Closer
	Size() int64
}

// ---------- file tunggal ----------

type fileSource struct {
	f    *os.File
	size int64
}

func (s *fileSource) ReadAt(p []byte, off int64) (int, error) { return s.f.ReadAt(p, off) }
func (s *fileSource) Close() error                            { return s.f.Close() }
func (s *fileSource) Size() int64                             { return s.size }

// ---------- view terbatas (mis. arsip + segmen recovery di belakangnya) ----------

type boundedSource struct {
	*io.SectionReader
	closer io.Closer
}

func (s *boundedSource) Close() error { return s.closer.Close() }

// ---------- SFX: view [base, base+size) di dalam file ----------

type sfxSource struct {
	*io.SectionReader
	f *os.File
}

func (s *sfxSource) Close() error { return s.f.Close() }

var sfxTrailerMagic = []byte{'Z', 'Y', 'N', 'X', 'S', 'F', 'X', 0x1a}

// ---------- multi-volume ----------

var volumeMagic = []byte{'Z', 'Y', 'N', 'X', 'V', 'O', 'L', 0x1a}

const volumeHeaderSize = 32 // [8 magic][8 idx LE][8 payloadLen LE][8 cadangan]

type volumeSet struct {
	parts  []*os.File
	starts []int64 // offset logis awal payload tiap volume
	lens   []int64
	total  int64
}

func (v *volumeSet) Size() int64 { return v.total }

func (v *volumeSet) Close() error {
	var first error
	for _, p := range v.parts {
		if err := p.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (v *volumeSet) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("offset negatif")
	}
	if off >= v.total {
		return 0, io.EOF
	}
	// volume terakhir yang starts[i] <= off
	i := sort.Search(len(v.starts), func(i int) bool { return v.starts[i] > off }) - 1
	read := 0
	for read < len(p) && i < len(v.parts) {
		local := off + int64(read) - v.starts[i]
		if local >= v.lens[i] {
			i++
			continue
		}
		want := int64(len(p) - read)
		if avail := v.lens[i] - local; want > avail {
			want = avail
		}
		n, err := v.parts[i].ReadAt(p[read:read+int(want)], volumeHeaderSize+local)
		read += n
		if err != nil && err != io.EOF {
			return read, err
		}
		if int64(n) < want {
			break
		}
	}
	if read < len(p) {
		return read, io.EOF
	}
	return read, nil
}

func volumePath(base string, idx int) string { return fmt.Sprintf("%s.%03d", base, idx) }

// openVolumeSet membuka rangkaian volume mulai dari .001 milik base.
func openVolumeSet(base string) (*volumeSet, error) {
	vs := &volumeSet{}
	for idx := 1; ; idx++ {
		f, err := os.Open(volumePath(base, idx))
		if err != nil {
			if idx == 1 {
				return nil, err
			}
			// Celah di tengah rangkaian? Volume setelahnya ada = ada yang hilang.
			if _, serr := os.Stat(volumePath(base, idx+1)); serr == nil {
				vs.Close()
				return nil, fmt.Errorf("volume %d hilang dari rangkaian", idx)
			}
			break
		}
		hdr := make([]byte, volumeHeaderSize)
		if _, err := f.ReadAt(hdr, 0); err != nil || !bytes.Equal(hdr[:8], volumeMagic) {
			f.Close()
			vs.Close()
			return nil, errors.New("header volume rusak")
		}
		gotIdx := binary.LittleEndian.Uint64(hdr[8:16])
		payload := int64(binary.LittleEndian.Uint64(hdr[16:24]))
		if int(gotIdx) != idx || payload < 0 {
			f.Close()
			vs.Close()
			return nil, fmt.Errorf("volume %d tidak berurutan/rusak", idx)
		}
		vs.parts = append(vs.parts, f)
		vs.starts = append(vs.starts, vs.total)
		vs.lens = append(vs.lens, payload)
		vs.total += payload
	}
	return vs, nil
}

// openSource membuka path sebagai ruang byte arsip logis:
// - bila path (atau path tanpa akhiran .NNN) adalah volume .001 -> volumeSet
// - bila file polos ber-trailer SFX -> view mulai offset arsip di dalamnya
// - selain itu file polos apa adanya
func openSource(path string) (archiveSource, error) {
	// deteksi volume: path persis berakhiran .001, atau path+".001" ada
	base := ""
	if len(path) > 4 && path[len(path)-4] == '.' && path[len(path)-3:] == "001" {
		base = path[:len(path)-4]
	} else if _, err := os.Stat(volumePath(path, 1)); err == nil {
		base = path
	}
	if base != "" {
		return openVolumeSet(base)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.Size() >= 16 {
		tail := make([]byte, 16)
		if _, err := f.ReadAt(tail, st.Size()-16); err == nil && bytes.Equal(tail[8:], sfxTrailerMagic) {
			baseOff := int64(binary.LittleEndian.Uint64(tail[0:8]))
			arcSize := st.Size() - 16 - baseOff
			if baseOff >= 0 && arcSize > 0 {
				return &sfxSource{SectionReader: io.NewSectionReader(f, baseOff, arcSize), f: f}, nil
			}
		}
	}
	return &fileSource{f: f, size: st.Size()}, nil
}
