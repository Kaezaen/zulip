package main

// Pembaca rantai blok untuk grup format v5: blok-blok solid independen
// didecode malas (lazy) satu per satu dan disambung menjadi satu aliran
// mentah grup, sehingga ekstrak/test streaming dengan RAM sebatas satu
// blok — termasuk untuk grup terenkripsi dan grup berfilter BCJ2/REP
// (keduanya didecode utuh per blok, bukan per grup).

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/ulikunitz/xz/lzma"
)

type combinedCloser struct {
	io.Reader
	c io.Closer
}

func (x *combinedCloser) Close() error { return x.c.Close() }

// openCodecReader membuka decoder codec atas aliran byte terkompresi.
func openCodecReader(codec byte, r io.Reader, dict []byte) (io.ReadCloser, error) {
	switch codec {
	case codecStore:
		return io.NopCloser(r), nil
	case codecZstd:
		opts := []zstd.DOption{zstd.WithDecoderMaxWindow(1 << 30)}
		if len(dict) > 0 {
			opts = append(opts, zstd.WithDecoderDicts(dict))
		}
		dec, err := zstd.NewReader(r, opts...)
		if err != nil {
			return nil, err
		}
		return closeWrap{Reader: dec, closeFn: dec.Close}, nil
	case codecLZMA2:
		cfg := lzma.Reader2Config{DictCap: 1 << 30}
		lr, err := cfg.NewReader2(r)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(lr), nil
	case codecBrotli:
		return io.NopCloser(brotli.NewReader(r)), nil
	}
	return nil, errUnknownCodec
}

type blockChainReader struct {
	f    archiveSource
	g    Group
	cc   *cryptoCtx
	dict []byte
	pos  int64 // offset chunk blok berikutnya di file
	next int   // indeks blok berikutnya yang belum dibuka
	cur  io.ReadCloser
	err  error
}

func newBlockChainReader(f archiveSource, g Group, cc *cryptoCtx) (*blockChainReader, error) {
	r := &blockChainReader{f: f, g: g, cc: cc, pos: g.FileOffset}
	if g.DictUsed {
		// readUvarintAt mengembalikan POSISI BARU (absolut), bukan jumlah byte.
		n, dataPos, err := readUvarintAt(f, r.pos)
		if err != nil {
			return nil, err
		}
		if n > 64<<20 {
			return nil, errors.New("panjang dictionary blok tidak wajar")
		}
		raw := make([]byte, n)
		if _, err := f.ReadAt(raw, dataPos); err != nil {
			return nil, err
		}
		r.pos = dataPos + int64(n)
		if cc != nil {
			d, err := cc.open(raw)
			if err != nil {
				return nil, err
			}
			r.dict = d
		} else {
			r.dict = raw
		}
	}
	return r, nil
}

func (r *blockChainReader) openBlock(i int) (io.ReadCloser, error) {
	meta := r.g.Blocks[i]
	var dict []byte
	if meta.DictUsed {
		dict = r.dict
	}
	var compStream io.Reader
	if r.cc != nil {
		n, dataPos, err := readUvarintAt(r.f, r.pos)
		if err != nil {
			return nil, err
		}
		if n > 1<<26 {
			return nil, errors.New("panjang chunk blok terenkripsi tidak wajar")
		}
		sealed := make([]byte, n)
		if _, err := r.f.ReadAt(sealed, dataPos); err != nil {
			return nil, err
		}
		r.pos = dataPos + int64(n)
		comp, err := r.cc.open(sealed)
		if err != nil {
			return nil, err
		}
		compStream = bytes.NewReader(comp)
	} else {
		compStream = io.NewSectionReader(r.f, r.pos, meta.CompSize)
		r.pos += meta.CompSize
	}
	if meta.Filter == filterBCJ2 || meta.Filter == filterREP {
		comp, err := io.ReadAll(compStream)
		if err != nil {
			return nil, err
		}
		dec, err := decodeGroup(meta.Codec, comp, dict, meta.RawSize)
		if err != nil {
			return nil, err
		}
		raw, err := applyFilter(meta.Filter, meta.Stride, dec, false)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(bytes.NewReader(raw)), nil
	}
	cr, err := openCodecReader(meta.Codec, compStream, dict)
	if err != nil {
		return nil, err
	}
	if meta.Filter != filterNone {
		w, ok := wrapFilterStream(cr, Group{Filter: meta.Filter, Stride: meta.Stride})
		if !ok {
			cr.Close()
			return nil, fmt.Errorf("blok %d: filter %d tidak bisa streaming", i, meta.Filter)
		}
		return &combinedCloser{Reader: w, c: cr}, nil
	}
	return cr, nil
}

func (r *blockChainReader) Read(p []byte) (int, error) {
	for {
		if r.cur == nil {
			if r.err != nil {
				return 0, r.err
			}
			if r.next >= len(r.g.Blocks) {
				r.err = io.EOF
				return 0, io.EOF
			}
			cur, err := r.openBlock(r.next)
			if err != nil {
				r.err = err
				return 0, err
			}
			r.cur = cur
			r.next++
		}
		n, err := r.cur.Read(p)
		if err == io.EOF {
			r.cur.Close()
			r.cur = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (r *blockChainReader) Close() error {
	if r.cur != nil {
		return r.cur.Close()
	}
	return nil
}
