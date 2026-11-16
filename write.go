package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/klauspost/compress/zstd"
)

type srcEntry struct {
	entry Entry
	disk  string
}

func collectInputs(inputs []string) ([]*srcEntry, error) {
	var out []*srcEntry
	for _, in := range inputs {
		info, err := os.Stat(in)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			out = append(out, &srcEntry{disk: in, entry: Entry{
				Name: filepath.Base(in), Ref: -1, Group: -1,
			}})
			continue
		}
		base := filepath.Base(filepath.Clean(in))
		err = filepath.Walk(in, func(p string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(in, p)
			if rel == "." {
				return nil
			}
			arc := base + "/" + filepath.ToSlash(rel)
			if fi.IsDir() {
				out = append(out, &srcEntry{entry: Entry{
					Name: arc, Dir: true, Ref: -1, Group: -1,
					Mode: uint32(fi.Mode().Perm()), ModUnix: fi.ModTime().UnixNano(),
				}})
				return nil
			}
			if !fi.Mode().IsRegular() {
				return nil // symlink & device dilewati (keamanan)
			}
			out = append(out, &srcEntry{disk: p, entry: Entry{Name: arc, Ref: -1, Group: -1}})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].entry.Name < out[j].entry.Name })
	return out, nil
}

// blockTarget: ukuran blok solid maksimum per grup (v0.5). Grup yang lebih
// besar dipecah menjadi blok-blok independen agar RAM penulis & pembaca
// terbatas sekitar satu blok, bukan sebesar arsip.
const blockTarget = 32 << 20

func adaptiveWindow(rawLen, capPow int) int {
	w := 1 << 20
	for w < rawLen && w < capPow {
		w <<= 1
	}
	if w > capPow {
		w = capPow
	}
	return w
}

type encodedGroup struct {
	codec    byte
	filter   byte
	stride   int
	comp     []byte
	dict     []byte
	dictUsed bool
}

func (e encodedGroup) total() int { return len(e.comp) + len(e.dict) }

// verify memastikan kandidat bisa didecode kembali persis sama dengan raw.
// Kandidat yang gagal verifikasi tidak akan pernah ditulis ke arsip.
func (e encodedGroup) verify(raw []byte) bool {
	dec, err := decodeGroup(e.codec, e.comp, e.dict, int64(len(raw)))
	if err != nil || len(dec) != len(raw) {
		return false
	}
	dec, err = applyFilter(e.filter, e.stride, dec, false)
	if err != nil {
		return false
	}
	return bytes.Equal(dec, raw)
}

func encodeBlock(raw []byte, dict []byte, mode string, isPE bool) (encodedGroup, error) {
	if len(raw) == 0 {
		return encodedGroup{codec: codecStore, comp: nil}, nil
	}
	store := encodedGroup{codec: codecStore, comp: raw}
	switch mode {
	case "fast":
		c, err := zstdEncode(raw, zstd.SpeedFastest, adaptiveWindow(len(raw), 1<<21), nil)
		if err != nil {
			return store, err
		}
		if len(c) < len(raw) {
			return encodedGroup{codec: codecZstd, comp: c}, nil
		}
		return store, nil
	case "normal":
		c, err := zstdEncode(raw, zstd.SpeedBestCompression, adaptiveWindow(len(raw), 1<<25), nil)
		if err != nil {
			return store, err
		}
		if len(c) < len(raw) {
			return encodedGroup{codec: codecZstd, comp: c}, nil
		}
		return store, nil
	default: // ultra: best-of semua kandidat, pemenang diverifikasi dulu
		best := store
		consider := func(e encodedGroup) {
			if e.total() < best.total() && e.verify(raw) {
				best = e
			}
		}
		win := adaptiveWindow(len(raw), 1<<27)
		dc := len(raw)
		if dc > 1<<26 {
			dc = 1 << 26
		}
		// Kandidat dievaluasi PARALEL (v0.8): ultra sekuensial menghabiskan
		// 117 dtk di corpus WinRAR pada VM 1,5 CPU karena Brotli q11,
		// LZMA2, dan saringan delta dicoba satu-satu. Hasil tiap kandidat
		// disimpan di slot, lalu consider() diterapkan dalam URUTAN ASLI
		// yang sama persis — keluaran byte-identik dengan versi sekuensial,
		// hanya lebih cepat di mesin multi-core.
		type slot struct {
			enc encodedGroup
			ok  bool
		}
		var sZstd, sZstdDict, sLzma, sBrotli slot
		var sBCJZ, sBCJL, sBCJ2Z, sBCJ2L, sBCJ2B slot
		var sDeltaZ, sDeltaL, sDeltaB, sREPZ, sREPL, sREPB slot
		workers := runtime.NumCPU()
		if workers < 2 {
			workers = 2
		}
		sem := make(chan struct{}, workers)
		var wg sync.WaitGroup
		run := func(f func()) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				f()
			}()
		}
		// Fase A: kandidat lapis pertama (saling bebas).
		run(func() {
			if comp, err := zstdEncode(raw, zstd.SpeedBestCompression, win, nil); err == nil {
				sZstd = slot{encodedGroup{codec: codecZstd, comp: comp}, true}
			}
		})
		if len(dict) > 0 && len(dict) < len(raw)/2 {
			run(func() {
				if comp, err := zstdEncode(raw, zstd.SpeedBestCompression, win, dict); err == nil {
					sZstdDict = slot{encodedGroup{codec: codecZstd, comp: comp, dict: dict, dictUsed: true}, true}
				}
			})
		}
		run(func() {
			if comp, err := lzma2Encode(raw, dc); err == nil {
				sLzma = slot{encodedGroup{codec: codecLZMA2, comp: comp}, true}
			}
		})
		if len(raw) <= 16<<20 { // brotli q11: kandidat terkuat teks & PE, dibatasi 16 MB
			run(func() {
				if comp, err := brotliEncode(raw); err == nil {
					sBrotli = slot{encodedGroup{codec: codecBrotli, comp: comp}, true}
				}
			})
		}
		var bcjFiltered, bcj2Filtered, repData []byte
		if isPE {
			run(func() {
				bcjFiltered = bcjEncode(raw)
				if comp, err := zstdEncode(bcjFiltered, zstd.SpeedBestCompression, win, nil); err == nil {
					sBCJZ = slot{encodedGroup{codec: codecZstd, filter: filterBCJ, comp: comp}, true}
				}
			})
			run(func() {
				bcj2Filtered = bcj2Encode(raw)
				if comp, err := zstdEncode(bcj2Filtered, zstd.SpeedBestCompression, win, nil); err == nil {
					sBCJ2Z = slot{encodedGroup{codec: codecZstd, filter: filterBCJ2, comp: comp}, true}
				}
			})
		}
		// Saringan delta: level WAJIB SpeedBetterCompression (terukur:
		// SpeedFastest/Default buta pada data delta PCM).
		bestStride := 0
		run(func() {
			bestScreen := len(raw) + 1
			for _, s := range []int{1, 2, 3, 4, 6, 8, 16} {
				d := deltaEncode(raw, s)
				if comp, err := zstdEncode(d, zstd.SpeedBetterCompression, win, nil); err == nil && len(comp) < bestScreen {
					bestStride, bestScreen = s, len(comp)
				}
			}
		})
		if len(raw) >= 128<<10 {
			run(func() {
				rep := repEncode(raw)
				if len(rep) < len(raw)*98/100 {
					repData = rep
					if comp, err := zstdEncode(rep, zstd.SpeedBestCompression, win, nil); err == nil {
						sREPZ = slot{encodedGroup{codec: codecZstd, filter: filterREP, comp: comp}, true}
					}
				}
			})
		}
		wg.Wait()
		plainZstd := len(raw) + 1
		if sZstd.ok {
			plainZstd = len(sZstd.enc.comp)
		}
		// Eskalasi per-codec: codec mahal untuk sebuah filter hanya dicoba
		// bila zstd terfilter yang sama mengalahkan zstd polos >= 1%
		// (gerbang global terbukti melewatkan delta2+brotli di corpus WAV).
		promising := func(compLen int) bool { return compLen < plainZstd*99/100 }
		// Fase B: eskalasi yang lolos gerbang, juga paralel.
		if sBCJZ.ok && promising(len(sBCJZ.enc.comp)) {
			run(func() {
				if comp, err := lzma2Encode(bcjFiltered, dc); err == nil {
					sBCJL = slot{encodedGroup{codec: codecLZMA2, filter: filterBCJ, comp: comp}, true}
				}
			})
		}
		if sBCJ2Z.ok && promising(len(sBCJ2Z.enc.comp)) {
			run(func() {
				if comp, err := lzma2Encode(bcj2Filtered, dc); err == nil {
					sBCJ2L = slot{encodedGroup{codec: codecLZMA2, filter: filterBCJ2, comp: comp}, true}
				}
			})
			if len(raw) <= 16<<20 {
				run(func() {
					if comp, err := brotliEncode(bcj2Filtered); err == nil {
						sBCJ2B = slot{encodedGroup{codec: codecBrotli, filter: filterBCJ2, comp: comp}, true}
					}
				})
			}
		}
		if bestStride > 0 {
			d := deltaEncode(raw, bestStride)
			run(func() {
				if comp, err := zstdEncode(d, zstd.SpeedBestCompression, win, nil); err == nil {
					sDeltaZ = slot{encodedGroup{codec: codecZstd, filter: filterDelta, stride: bestStride, comp: comp}, true}
				}
			})
			wg.Wait()
			if sDeltaZ.ok && promising(len(sDeltaZ.enc.comp)) {
				run(func() {
					if comp, err := lzma2Encode(d, dc); err == nil {
						sDeltaL = slot{encodedGroup{codec: codecLZMA2, filter: filterDelta, stride: bestStride, comp: comp}, true}
					}
				})
				if len(raw) <= 16<<20 {
					run(func() {
						if comp, err := brotliEncode(d); err == nil {
							sDeltaB = slot{encodedGroup{codec: codecBrotli, filter: filterDelta, stride: bestStride, comp: comp}, true}
						}
					})
				}
			}
		}
		if sREPZ.ok && promising(len(sREPZ.enc.comp)) {
			run(func() {
				if comp, err := lzma2Encode(repData, dc); err == nil {
					sREPL = slot{encodedGroup{codec: codecLZMA2, filter: filterREP, comp: comp}, true}
				}
			})
			if len(repData) <= 16<<20 {
				run(func() {
					if comp, err := brotliEncode(repData); err == nil {
						sREPB = slot{encodedGroup{codec: codecBrotli, filter: filterREP, comp: comp}, true}
					}
				})
			}
		}
		wg.Wait()
		// Terapkan dalam urutan asli: pemenang & seri identik sekuensial.
		for _, s := range []slot{sZstd, sZstdDict, sLzma, sBrotli,
			sBCJZ, sBCJL, sBCJ2Z, sBCJ2L, sBCJ2B,
			sDeltaZ, sDeltaL, sDeltaB, sREPZ, sREPL, sREPB} {
			if s.ok {
				consider(s.enc)
			}
		}
		return best, nil
	}
}

type addOptions struct {
	password    string
	volumeSize  int64 // 0 = file tunggal
	recoveryPct int   // 0 = tanpa recovery record
	sfx         bool
}

func cmdAdd(mode, archivePath string, inputs []string, opts addOptions) error {
	started := time.Now()
	password := opts.password
	// Konfirmasi timpa di terminal: arsip lama tidak senyap diganti.
	if uiStdin {
		if _, err := os.Stat(archivePath); err == nil {
			fmt.Printf("Arsip %s sudah ada. Timpa? [y/N] ", archivePath)
			var ans string
			fmt.Scanln(&ans)
			if ans != "y" && ans != "Y" {
				return errors.New("dibatalkan pengguna")
			}
		}
	}
	srcs, err := collectInputs(inputs)
	if err != nil {
		return err
	}
	// Total ukuran dulu (stat murah) agar progress punya penyebut.
	var scanTotal int64
	for _, s := range srcs {
		if s.entry.Dir {
			continue
		}
		if fi, err := os.Stat(s.disk); err == nil {
			scanTotal += fi.Size()
		}
	}
	prog := newProgress("Memindai", scanTotal)
	seen := map[string]int{}
	var totalRaw int64
	for i, s := range srcs {
		if s.entry.Dir {
			continue
		}
		// Hash streaming: isi file tidak pernah dimuat utuh ke RAM (v0.5).
		fi, err := os.Stat(s.disk)
		if err != nil {
			prog.finish()
			return err
		}
		fh, err := os.Open(s.disk)
		if err != nil {
			prog.finish()
			return err
		}
		h := sha256.New()
		_, cerr := io.CopyBuffer(h, fh, make([]byte, 1<<20))
		fh.Close()
		if cerr != nil {
			prog.finish()
			return cerr
		}
		prog.add(fi.Size())
		s.entry.Size = fi.Size()
		s.entry.Mode = uint32(fi.Mode().Perm())
		s.entry.ModUnix = fi.ModTime().UnixNano()
		sum := h.Sum(nil)
		s.entry.SHA256 = hex.EncodeToString(sum)
		totalRaw += fi.Size()
		if prev, ok := seen[s.entry.SHA256]; ok && srcs[prev].entry.Size == s.entry.Size {
			s.entry.Ref = prev
		} else {
			seen[s.entry.SHA256] = i
		}
	}
	groupIdx := map[string][]int{}
	var keys []string
	for i, s := range srcs {
		if s.entry.Dir || s.entry.Ref >= 0 {
			continue
		}
		key := groupKey(s.entry.Name)
		if _, ok := groupIdx[key]; !ok {
			keys = append(keys, key)
		}
		groupIdx[key] = append(groupIdx[key], i)
	}
	sort.Strings(keys)

	idx := &Index{Version: 5, Mode: mode}
	if opts.sfx && opts.volumeSize > 0 {
		return errors.New("--sfx tidak bisa digabung multi-volume")
	}
	if opts.recoveryPct > 0 && opts.volumeSize > 0 {
		return errors.New("recovery record belum mendukung multi-volume")
	}
	// Tujuan tulis selalu file sementara; hasil akhir di-rename secara
	// atomik di ujung (v0.5): arsip tujuan tidak pernah tertimpa parsial.
	targetPath := archivePath + ".tmp-zynx"
	success := false
	defer func() {
		if success {
			return
		}
		os.Remove(targetPath)
		if opts.volumeSize > 0 {
			for i := 1; ; i++ {
				if err := os.Remove(volumePath(targetPath, i)); err != nil {
					break
				}
			}
		}
	}()
	var sink io.Writer
	var volW *volumeWriter
	var fileW *os.File
	if opts.volumeSize > 0 {
		volW, err = newVolumeWriter(targetPath, opts.volumeSize)
		if err != nil {
			return err
		}
		sink = volW
	} else {
		fileW, err = os.Create(targetPath)
		if err != nil {
			return err
		}
		sink = fileW
	}
	out := &countingWriter{w: sink}
	closeSink := func() error {
		if volW != nil {
			return volW.Close()
		}
		return fileW.Close()
	}
	defer closeSink()
	if _, err := out.Write(magicHeader); err != nil {
		return err
	}
	var cc *cryptoCtx
	var offset int64 = int64(len(magicHeader))
	if password != "" {
		var salt []byte
		cc, salt, err = newWriteCrypto(password)
		if err != nil {
			return err
		}
		hdr := []byte{1}
		hdr = append(hdr, salt...)
		var tmp [binary.MaxVarintLen64]byte
		for _, v := range []uint64{uint64(argonTime), uint64(argonMemKiB), uint64(argonThreads)} {
			n := binary.PutUvarint(tmp[:], v)
			hdr = append(hdr, tmp[:n]...)
		}
		if _, err := out.Write(hdr); err != nil {
			return err
		}
		offset += int64(len(hdr))
	} else {
		if _, err := out.Write([]byte{0}); err != nil {
			return err
		}
		offset++
	}
	// Kepala keluaran: arsip tujuan + fitur aktif, satu pandangan.
	{
		feat := modeLabel(mode)
		if password != "" {
			feat += " · terenkripsi"
		}
		if opts.volumeSize > 0 {
			feat += " · multi-volume " + humanSize(opts.volumeSize)
		}
		if opts.recoveryPct > 0 {
			feat += fmt.Sprintf(" · recovery %d%%", opts.recoveryPct)
		}
		if opts.sfx {
			feat += " · SFX"
		}
		prog.finish()
		fmt.Printf("%s %s\n  %s\n", bold("Mengarsipkan"), bold(archivePath), dim(feat))
		prog = newProgress("Mengompres", totalRaw)
	}
	spool, err := os.CreateTemp("", "zynx-spool-*")
	if err != nil {
		return err
	}
	defer func() { spool.Close(); os.Remove(spool.Name()) }()

	for gid, key := range keys {
		members := groupIdx[key]
		sort.Slice(members, func(a, b int) bool {
			ea, eb := srcs[members[a]].entry, srcs[members[b]].entry
			if ea.Size != eb.Size {
				return ea.Size < eb.Size
			}
			return ea.Name < eb.Name
		})
		// Sampel untuk melatih dictionary grup (terbatas, dari potongan
		// awal beberapa file pertama).
		var samples [][]byte
		for _, mi := range members {
			if len(samples) >= 16 {
				break
			}
			s := srcs[mi]
			if s.entry.Size == 0 {
				continue
			}
			fh, err := os.Open(s.disk)
			if err != nil {
				return err
			}
			b := make([]byte, 64<<10)
			n, _ := io.ReadFull(fh, b)
			fh.Close()
			if n > 0 {
				samples = append(samples, b[:n])
			}
		}
		var dict []byte
		if mode != "fast" && len(samples) >= 4 {
			if d, err := buildDict(samples); err == nil && len(d) > 0 {
				dict = d
			}
		}
		// Rakit grup dari disk per blok (maks blockTarget byte mentah):
		// blok di-encode segera dan hasilnya di-spool ke file sementara,
		// jadi RAM hanya menampung satu blok + kandidat-kandidatnya.
		g := Group{ID: gid, Key: key}
		if _, err := spool.Seek(0, io.SeekStart); err != nil {
			return err
		}
		if err := spool.Truncate(0); err != nil {
			return err
		}
		var spoolOffs []int64
		blockBuf := &bytes.Buffer{}
		flushBlock := func() error {
			if blockBuf.Len() == 0 && len(g.Blocks) > 0 {
				return nil
			}
			enc, err := encodeBlock(blockBuf.Bytes(), dict, mode, key == ".pe")
			if err != nil {
				return err
			}
			off, err := spool.Seek(0, io.SeekCurrent)
			if err != nil {
				return err
			}
			if _, err := spool.Write(enc.comp); err != nil {
				return err
			}
			spoolOffs = append(spoolOffs, off)
			g.Blocks = append(g.Blocks, BlockMeta{
				Codec: enc.codec, Filter: enc.filter, Stride: enc.stride,
				RawSize: int64(blockBuf.Len()), CompSize: int64(len(enc.comp)),
				DictUsed: enc.dictUsed,
			})
			if enc.dictUsed {
				g.DictUsed = true
			}
			g.RawSize += int64(blockBuf.Len())
			prog.add(int64(blockBuf.Len()))
			blockBuf.Reset()
			return nil
		}
		chunk := make([]byte, 256<<10)
		for _, mi := range members {
			s := srcs[mi]
			s.entry.Group = gid
			s.entry.Offset = g.RawSize + int64(blockBuf.Len())
			fh, err := os.Open(s.disk)
			if err != nil {
				return err
			}
			for {
				n, rerr := fh.Read(chunk)
				if n > 0 {
					blockBuf.Write(chunk[:n])
					if blockBuf.Len() >= blockTarget {
						if err := flushBlock(); err != nil {
							fh.Close()
							return err
						}
					}
				}
				if rerr == io.EOF {
					break
				}
				if rerr != nil {
					fh.Close()
					return rerr
				}
			}
			fh.Close()
		}
		if err := flushBlock(); err != nil {
			return err
		}
		if g.DictUsed {
			g.DictSize = len(dict)
		}
		g.Codec, g.Filter, g.Stride = g.Blocks[0].Codec, g.Blocks[0].Filter, g.Blocks[0].Stride
		// Emisi segmen v5: [chunk dict bila ada][blok...]; per chunk bila
		// terenkripsi: [uvarint len][sealed], bila tidak: byte mentah.
		g.FileOffset = offset
		var hdr [binary.MaxVarintLen64]byte
		writeChunk := func(data []byte) error {
			if cc != nil {
				sealed, err := cc.seal(data)
				if err != nil {
					return err
				}
				m := binary.PutUvarint(hdr[:], uint64(len(sealed)))
				if _, err := out.Write(hdr[:m]); err != nil {
					return err
				}
				if _, err := out.Write(sealed); err != nil {
					return err
				}
				offset += int64(m) + int64(len(sealed))
				return nil
			}
			if _, err := out.Write(data); err != nil {
				return err
			}
			offset += int64(len(data))
			return nil
		}
		if g.DictUsed {
			if cc != nil {
				if err := writeChunk(dict); err != nil {
					return err
				}
			} else {
				m := binary.PutUvarint(hdr[:], uint64(len(dict)))
				if _, err := out.Write(hdr[:m]); err != nil {
					return err
				}
				offset += int64(m)
				if err := writeChunk(dict); err != nil {
					return err
				}
			}
		}
		for bi, bm := range g.Blocks {
			if _, err := spool.Seek(spoolOffs[bi], io.SeekStart); err != nil {
				return err
			}
			if cc != nil {
				comp := make([]byte, bm.CompSize)
				if _, err := io.ReadFull(spool, comp); err != nil {
					return err
				}
				if err := writeChunk(comp); err != nil {
					return err
				}
			} else {
				if _, err := io.CopyN(out, spool, bm.CompSize); err != nil {
					return err
				}
				offset += bm.CompSize
			}
		}
		g.CompSize = offset - g.FileOffset
		idx.Groups = append(idx.Groups, g)
		marks := ""
		if g.DictUsed {
			marks += "+dict"
		}
		switch g.Filter {
		case filterBCJ:
			marks += "+bcj"
		case filterBCJ2:
			marks += "+bcj2"
		case filterDelta:
			marks += fmt.Sprintf("+delta%d", g.Stride)
		case filterREP:
			marks += "+rep"
		}
		blokNote := ""
		if len(g.Blocks) > 1 {
			blokNote = fmt.Sprintf(" · %d blok", len(g.Blocks))
		}
		fmt.Printf("  %s %-8s %3d file  %10s %s %10s  %s\n",
			accent("▸"), keyOrNone(key), len(members), humanSize(g.RawSize), dim("→"),
			humanSize(g.CompSize), dim(codecName(g.Codec)+marks+blokNote))
	}
	// Urutan entri untuk index v4: dir, lalu fisik per (grup, offset), lalu
	// ref. Ref di-remap ke posisi barunya agar tetap menunjuk sumbernya.
	var dirs, phys, refs []int
	for i, s := range srcs {
		switch {
		case s.entry.Dir:
			dirs = append(dirs, i)
		case s.entry.Ref >= 0:
			refs = append(refs, i)
		default:
			phys = append(phys, i)
		}
	}
	sort.Slice(phys, func(a, b int) bool {
		ea, eb := srcs[phys[a]].entry, srcs[phys[b]].entry
		if ea.Group != eb.Group {
			return ea.Group < eb.Group
		}
		return ea.Offset < eb.Offset
	})
	order := append(append(dirs, phys...), refs...)
	newPos := make([]int, len(srcs))
	for np, si := range order {
		newPos[si] = np
	}
	for _, si := range order {
		e := srcs[si].entry
		if e.Ref >= 0 {
			e.Ref = newPos[e.Ref]
		}
		idx.Entries = append(idx.Entries, e)
	}
	indexOffset := offset
	ib := idx.marshalBinary()
	// Segmen index = [1 byte flag: 0=mentah, 1=zstd][data]
	// Bila terenkripsi, data = seal(index polos/terkompresi).
	payload := ib
	flag := byte(0)
	if comp, err := zstdEncode(ib, zstd.SpeedBestCompression, 1<<20, nil); err == nil && len(comp) < len(ib) {
		payload, flag = comp, 1
	}
	if cc != nil {
		sealed, err := cc.seal(payload)
		if err != nil {
			return err
		}
		payload = sealed
	}
	seg := append([]byte{flag}, payload...)
	if _, err := out.Write(seg); err != nil {
		return err
	}
	var foot [16]byte
	binary.LittleEndian.PutUint64(foot[0:8], uint64(indexOffset))
	copy(foot[8:16], magicFooter)
	if _, err := out.Write(foot[:]); err != nil {
		return err
	}
	if err := closeSink(); err != nil {
		return err
	}
	if opts.recoveryPct > 0 {
		if err := addRecoveryRecord(targetPath, opts.recoveryPct); err != nil {
			return err
		}
	}
	arcSize := out.n
	if opts.recoveryPct > 0 {
		if st, err := os.Stat(targetPath); err == nil {
			arcSize = st.Size()
		}
	}
	// Rename atomik ke tujuan akhir.
	if opts.sfx {
		tmpSfx := archivePath + ".tmp-sfx"
		if err := wrapSFX(targetPath, tmpSfx); err != nil {
			os.Remove(tmpSfx)
			return err
		}
		if err := os.Rename(tmpSfx, archivePath); err != nil {
			os.Remove(tmpSfx)
			return err
		}
	} else if volW != nil {
		for _, fn := range volW.files {
			final := strings.Replace(fn, ".tmp-zynx.", ".", 1)
			if err := os.Rename(fn, final); err != nil {
				return err
			}
		}
	} else {
		if err := os.Rename(targetPath, archivePath); err != nil {
			return err
		}
		if st, err := os.Stat(archivePath); err == nil && opts.recoveryPct == 0 {
			arcSize = st.Size()
		}
	}
	success = true
	prog.finish()
	ratio := 0.0
	if totalRaw > 0 {
		ratio = float64(arcSize) / float64(totalRaw) * 100
	}
	printAddSummary(archivePath, len(idx.Entries), totalRaw, arcSize, ratio, started, volW, opts)
	return nil
}

// modeLabel menerjemahkan mode internal ke label yang tampil.
func modeLabel(mode string) string {
	switch mode {
	case "fast":
		return "mode fast"
	case "ultra":
		return "mode ultra"
	default:
		return "mode normal"
	}
}

// printAddSummary mencetak kartu ringkasan akhir pembuatan arsip:
// hasil, rasio dengan bar visual, lama proses, dan langkah lanjutan.
func printAddSummary(archivePath string, nEntries int, totalRaw, arcSize int64, ratio float64, started time.Time, volW *volumeWriter, opts addOptions) {
	sizeNote := humanSize(arcSize)
	if opts.sfx {
		sizeNote += " (SFX: stub + arsip)"
	}
	if volW != nil {
		sizeNote += fmt.Sprintf(" dalam %d volume", len(volW.files))
	}
	fmt.Printf("%s Selesai dalam %s\n", okCol("✓"), humanDur(time.Since(started)))
	fmt.Printf("  Arsip  %s — %s\n", bold(archivePath), sizeNote)
	fmt.Printf("  Isi    %d entri · %s asli\n", nEntries, humanSize(totalRaw))
	if totalRaw > 0 {
		fmt.Printf("  Rasio  %s %s — hemat %s\n", ratioBar(ratio, 20),
			percentID(ratio), percentID(100-ratio))
	}
	fmt.Printf("  %s\n", dim("Lanjut: zulip x "+archivePath+" · zulip t "+archivePath))
}

// percentID memformat persen dengan koma desimal ala Indonesia.
func percentID(v float64) string {
	return strings.Replace(fmt.Sprintf("%.1f%%", v), ".", ",", 1)
}

// groupKey memetakan ekstensi ke grup solid. Binary PE (.exe/.dll/.sfx/...)
// disatukan: mereka berbagi pola lintas-file yang besar, memisahnya per
// ekstensi membuang redundansi itu (pelajaran dari benchmark folder WinRAR).
func groupKey(name string) string {
	ext := strings.ToLower(filepath.Ext(name))
	switch ext {
	case ".exe", ".dll", ".sfx", ".sys", ".ocx", ".com", ".scr":
		return ".pe"
	}
	return ext
}

func keyOrNone(k string) string {
	if k == "" {
		return "(none)"
	}
	return k
}
