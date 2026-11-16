package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

)

var errUnknownCodec = errors.New("codec tidak dikenal")

// zstd.Decoder.Close() tidak mengembalikan error, jadi tidak langsung
// memenuhi io.ReadCloser — bungkus manual.
type closeWrap struct {
	io.Reader
	closeFn func()
}

func (c closeWrap) Close() error { c.closeFn(); return nil }

func openArchive(path string, password string) (*Index, archiveSource, *cryptoCtx, error) {
	f, err := openSource(path)
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(e error) (*Index, archiveSource, *cryptoCtx, error) { f.Close(); return nil, nil, nil, e }
	// Segmen recovery (bila ada) menempel setelah footer: batasi view ke
	// wilayah arsip yang dicakupnya agar logika footer/index tidak bergeser.
	var rec *recoveryInfo
	if ri := detectRecovery(f, f.Size()); ri != nil {
		rec = ri
		f = &boundedSource{SectionReader: io.NewSectionReader(f, 0, ri.CoveredLen), closer: f}
	}
	if f.Size() < int64(len(magicHeader)+16) {
		return fail(errors.New("file terlalu kecil, bukan .zynx/.adit"))
	}
	hdr := make([]byte, len(magicHeader))
	if _, err := f.ReadAt(hdr, 0); err != nil {
		return fail(err)
	}
	hasHeader := bytes.Equal(hdr, magicHeader) || bytes.Equal(hdr, magicHeaderV4) || bytes.Equal(hdr, magicHeaderV3)
	if !hasHeader && !bytes.Equal(hdr, magicHeaderV2) && !bytes.Equal(hdr, magicHeaderV1) {
		return fail(errors.New("magic salah, bukan .zynx v5/v4/v3/v2 / .adit v1"))
	}
	var cc *cryptoCtx
	if hasHeader {
		one := make([]byte, 1)
		if _, err := f.ReadAt(one, int64(len(magicHeader))); err != nil {
			return fail(err)
		}
		if one[0]&1 != 0 {
			if password == "" {
				return fail(errors.New("arsip terenkripsi: berikan password dengan -p"))
			}
			salt := make([]byte, saltLen)
			if _, err := f.ReadAt(salt, int64(len(magicHeader))+1); err != nil {
				return fail(err)
			}
			raw := make([]byte, 40)
			if _, err := f.ReadAt(raw, int64(len(magicHeader))+1+saltLen); err != nil {
				return fail(err)
			}
			var params [3]uint32
			off := 0
			for i := 0; i < 3; i++ {
				v, n := binary.Uvarint(raw[off:])
				if n <= 0 {
					return fail(errors.New("header enkripsi rusak"))
				}
				params[i] = uint32(v)
				off += n
			}
			cc = newReadCrypto(password, salt, params[0], params[1], params[2])
		}
	}
	foot := make([]byte, 16)
	if _, err := f.ReadAt(foot, f.Size()-16); err != nil {
		return fail(err)
	}
	if !bytes.Equal(foot[8:16], magicFooter) && !bytes.Equal(foot[8:16], magicFooterV1) {
		return fail(errors.New("footer rusak"))
	}
	indexOffset := int64(binary.LittleEndian.Uint64(foot[0:8]))
	// indexOffset dari footer bisa negatif (bit tertinggi) atau menunjuk
	// keluar file pada arsip rusak — validasi SEBELUM alokasi (temuan fuzz:
	// makeslice len out of range).
	if indexOffset < 0 || indexOffset > f.Size()-16 {
		return fail(errors.New("offset index di luar file"))
	}
	indexLen := f.Size() - 16 - indexOffset
	if indexLen <= 1 {
		return fail(errors.New("index rusak"))
	}
	seg := make([]byte, indexLen)
	if _, err := f.ReadAt(seg, indexOffset); err != nil {
		return fail(err)
	}
	ib := seg[1:]
	if cc != nil {
		ib, err = cc.open(ib)
		if err != nil {
			return fail(err)
		}
	}
	if seg[0] == 1 {
		ib, err = zstdDecode(ib, nil, 0)
		if err != nil {
			return fail(fmt.Errorf("index terkompresi rusak: %w", err))
		}
	}
	if len(ib) > 0 && ib[0] == '{' { // v0.1: index JSON
		idx, err := unmarshalIndexJSON(ib)
		if err != nil {
			return fail(fmt.Errorf("index JSON tidak valid: %w", err))
		}
		idx.Recovery = rec
		return idx, f, cc, nil
	}
	idx, err := unmarshalIndexBinary(ib)
	if err != nil {
		return fail(fmt.Errorf("index biner tidak valid: %w", err))
	}
	idx.Recovery = rec
	return idx, f, cc, nil
}

// groupDict membaca dictLen + dict grup, mengembalikan posisi awal data terkompresi.
func groupDict(f archiveSource, g Group) (dict []byte, dataStart int64, err error) {
	var dictLen uint64
	shift := uint(0)
	pos := g.FileOffset
	one := make([]byte, 1)
	for {
		if _, err := f.ReadAt(one, pos); err != nil {
			return nil, 0, err
		}
		pos++
		dictLen |= uint64(one[0]&0x7f) << shift
		if one[0]&0x80 == 0 {
			break
		}
		shift += 7
		if shift > 63 {
			return nil, 0, errors.New("dictLen varint rusak")
		}
	}
	if dictLen > uint64(g.CompSize) || dictLen > 64<<20 {
		return nil, 0, errors.New("panjang dictionary grup tidak wajar")
	}
	dict = make([]byte, dictLen)
	if dictLen > 0 {
		if _, err := f.ReadAt(dict, pos); err != nil {
			return nil, 0, err
		}
		pos += int64(dictLen)
	}
	return dict, pos, nil
}

// readUvarintAt membaca satu uvarint dari file pada posisi pos.
func readUvarintAt(f archiveSource, pos int64) (uint64, int64, error) {
	var v uint64
	shift := uint(0)
	one := make([]byte, 1)
	for {
		if _, err := f.ReadAt(one, pos); err != nil {
			return 0, 0, err
		}
		pos++
		v |= uint64(one[0]&0x7f) << shift
		if one[0]&0x80 == 0 {
			return v, pos, nil
		}
		shift += 7
		if shift > 63 {
			return 0, 0, errors.New("varint rusak")
		}
	}
}

// readGroupPlain mengambil (dict, comp) mentah satu grup, membuka enkripsi
// segmen terlebih dahulu bila arsip terenkripsi.
func readGroupPlain(f archiveSource, g Group, cc *cryptoCtx) (dict, comp []byte, err error) {
	if cc == nil {
		var dataStart int64
		dict, dataStart, err = groupDict(f, g)
		if err != nil {
			return nil, nil, err
		}
		comp = make([]byte, g.CompSize)
		if g.CompSize > 0 {
			if _, err := f.ReadAt(comp, dataStart); err != nil {
				return nil, nil, err
			}
		}
		return dict, comp, nil
	}
	cipherLen, pos, err := readUvarintAt(f, g.FileOffset)
	if err != nil {
		return nil, nil, err
	}
	sealed := make([]byte, cipherLen)
	if _, err := f.ReadAt(sealed, pos); err != nil {
		return nil, nil, err
	}
	plain, err := cc.open(sealed)
	if err != nil {
		return nil, nil, err
	}
	r := bytes.NewReader(plain)
	dictLen, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, nil, err
	}
	dict = make([]byte, dictLen)
	if _, err := io.ReadFull(r, dict); err != nil {
		return nil, nil, err
	}
	comp = make([]byte, r.Len())
	if _, err := io.ReadFull(r, comp); err != nil {
		return nil, nil, err
	}
	return dict, comp, nil
}

// readGroupFull mendecode satu grup utuh ke RAM (grup berfilter atau terenkripsi).
func readGroupFull(f archiveSource, g Group, cc *cryptoCtx) ([]byte, error) {
	dict, comp, err := readGroupPlain(f, g, cc)
	if err != nil {
		return nil, err
	}
	raw, err := decodeGroup(g.Codec, comp, dict, g.RawSize)
	if err != nil {
		return nil, err
	}
	raw, err = applyFilterDecode(g.Filter, g.Stride, raw)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) != g.RawSize {
		return nil, fmt.Errorf("grup %d: ukuran decode %d != %d", g.ID, len(raw), g.RawSize)
	}
	return raw, nil
}

// openGroupReader membuka decoder streaming untuk satu grup (format <= v4).
func openGroupReader(f archiveSource, g Group) (io.ReadCloser, error) {
	dict, dataStart, err := groupDict(f, g)
	if err != nil {
		return nil, err
	}
	section := io.NewSectionReader(f, dataStart, g.CompSize)
	return openCodecReader(g.Codec, section, dict)
}

// processGroup mengalirkan isi grup entri per entri (urut offset) ke handler.
// Handler menerima reader terbatas tepat sebesar entri dan WAJIB menghabiskannya.
func processGroup(idx *Index, f archiveSource, g Group, cc *cryptoCtx, handle func(e Entry, r io.Reader) error) error {
	var phys []Entry
	for _, e := range idx.Entries {
		if !e.Dir && e.Ref < 0 && e.Group == g.ID {
			phys = append(phys, e)
		}
	}
	sort.Slice(phys, func(i, j int) bool { return phys[i].Offset < phys[j].Offset })
	if len(phys) == 0 {
		return nil
	}
	if idx.Version >= 5 {
		r, err := newBlockChainReader(f, g, cc)
		if err != nil {
			return err
		}
		defer r.Close()
		return serveStream(phys, r, handle)
	}
	// Jalur buffered hanya untuk: arsip terenkripsi (AEAD utuh per segmen),
	// filter BCJ2 (stream samping tersimpan setelah stream utama), dan REP
	// (salin dari riwayat grup penuh). Delta & BCJ kini streaming.
	buffered := cc != nil || (g.Filter != filterNone && g.Filter != filterDelta && g.Filter != filterBCJ)
	if buffered {
		raw, err := readGroupFull(f, g, cc)
		if err != nil {
			return err
		}
		for _, e := range phys {
			end := e.Offset + e.Size
			if end > int64(len(raw)) {
				return fmt.Errorf("entri %s keluar dari grup", e.Name)
			}
			if err := handle(e, bytes.NewReader(raw[e.Offset:end])); err != nil {
				return err
			}
		}
		return nil
	}
	cr, err := openGroupReader(f, g)
	if err != nil {
		return err
	}
	defer cr.Close()
	var r io.Reader = cr
	if g.Filter != filterNone {
		wrapped, ok := wrapFilterStream(cr, g)
		if !ok {
			return fmt.Errorf("grup %d: filter %d tidak bisa streaming", g.ID, g.Filter)
		}
		r = wrapped
	}
	return serveStream(phys, r, handle)
}

// serveStream menyajikan entri-entri fisik (urut offset) dari aliran mentah
// grup ke handler; handler wajib menghabiskan reader yang diberikan.
func serveStream(phys []Entry, r io.Reader, handle func(e Entry, r io.Reader) error) error {
	var cur int64
	for _, e := range phys {
		if skip := e.Offset - cur; skip > 0 {
			if _, err := io.CopyN(io.Discard, r, skip); err != nil {
				return err
			}
			cur += skip
		} else if skip < 0 {
			return fmt.Errorf("entri %s: offset mundur", e.Name)
		}
		if err := handle(e, io.LimitReader(r, e.Size)); err != nil {
			return err
		}
		cur += e.Size
	}
	return nil
}

func verifyHash(e Entry, sum []byte) error {
	if hex.EncodeToString(sum) != e.SHA256 {
		return fmt.Errorf("%s: SHA-256 tidak cocok (arsip rusak / data berubah)", e.Name)
	}
	return nil
}

func refsBySource(idx *Index) map[int][]int {
	m := map[int][]int{}
	for i, e := range idx.Entries {
		if e.Ref >= 0 {
			m[e.Ref] = append(m[e.Ref], i)
		}
	}
	return m
}

func cmdList(path string, password string) error {
	started := time.Now()
	idx, f, cc, err := openArchive(path, password)
	if err != nil {
		return err
	}
	defer f.Close()
	encNote := ""
	if cc != nil {
		encNote = " · terenkripsi"
	}
	fmt.Printf("%s %s %s\n", bold("Arsip"), bold(path),
		dim(fmt.Sprintf("· format v%d · %s%s", idx.Version, modeLabel(idx.Mode), encNote)))
	fmt.Printf("  %s  %s  %s\n", dim(fmt.Sprintf("%10s", "UKURAN")), dim(fmt.Sprintf("%-16s", "DIUBAH")), dim("NAMA"))
	var total, compTotal int64
	for _, e := range idx.Entries {
		name := e.Name
		if e.Dir {
			name += "/"
		}
		when := "-"
		if e.ModUnix > 0 {
			when = time.Unix(0, e.ModUnix).Format("2006-01-02 15:04")
		}
		dup := ""
		if e.Ref >= 0 {
			dup = dim("  (duplikat dari " + idx.Entries[e.Ref].Name + ")")
		}
		fmt.Printf("  %10s  %-16s  %s%s\n", humanSize(e.Size), when, name, dup)
		total += e.Size
	}
	for _, g := range idx.Groups {
		compTotal += g.CompSize
	}
	recNote := ""
	if idx.Recovery != nil {
		recNote = fmt.Sprintf(" · recovery RS-%d%%", idx.Recovery.Pct)
	}
	ratioNote := ""
	if total > 0 {
		ratioNote = fmt.Sprintf(" (%s)", percentID(float64(compTotal)/float64(total)*100))
	}
	fmt.Printf("  %s\n", dim(fmt.Sprintf("Total %s dalam %d entri · terkompresi %s%s%s · %s",
		humanSize(total), len(idx.Entries), humanSize(compTotal), ratioNote, recNote, humanDur(time.Since(started)))))
	for _, g := range idx.Groups {
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
		fmt.Printf("  %s %-8s %10s %s %10s  %s\n", accent("▸"), keyOrNone(g.Key),
			humanSize(g.RawSize), dim("→"), humanSize(g.CompSize), dim(codecName(g.Codec)+marks))
	}
	return nil
}

// cmdListJSON mencetak daftar isi sebagai JSON — dipakai GUI zulip
// dan alat lain yang butuh keluaran terbaca mesin.
func cmdListJSON(path string, password string) error {
	idx, f, cc, err := openArchive(path, password)
	if err != nil {
		return err
	}
	defer f.Close()
	type jEntry struct {
		Name  string `json:"name"`
		Size  int64  `json:"size"`
		Dir   bool   `json:"dir"`
		Mod   int64  `json:"mod_unix_nano"`
		Dedup bool   `json:"dedup"`
	}
	type jGroup struct {
		Key  string `json:"key"`
		Codec string `json:"codec"`
		Raw  int64  `json:"raw"`
		Comp int64  `json:"comp"`
	}
	out := struct {
		Version   int      `json:"version"`
		Mode      string   `json:"mode"`
		Encrypted bool     `json:"encrypted"`
		Entries   []jEntry `json:"entries"`
		Groups    []jGroup `json:"groups"`
	}{Version: idx.Version, Mode: idx.Mode, Encrypted: cc != nil}
	for _, e := range idx.Entries {
		out.Entries = append(out.Entries, jEntry{e.Name, e.Size, e.Dir, e.ModUnix, e.Ref >= 0})
	}
	for _, g := range idx.Groups {
		out.Groups = append(out.Groups, jGroup{keyOrNone(g.Key), codecName(g.Codec), g.RawSize, g.CompSize})
	}
	enc := json.NewEncoder(os.Stdout)
	return enc.Encode(out)
}

func cmdTest(path string, password string) error {
	started := time.Now()
	idx, f, cc, err := openArchive(path, password)
	if err != nil {
		return err
	}
	defer f.Close()
	var totalRaw int64
	for _, g := range idx.Groups {
		totalRaw += g.RawSize
	}
	prog := newProgress("Menguji", totalRaw)
	refs := refsBySource(idx)
	n := 0
	for _, g := range idx.Groups {
		err := processGroup(idx, f, g, cc, func(e Entry, r io.Reader) error {
			h := sha256.New()
			if _, err := io.Copy(h, r); err != nil {
				return err
			}
			if err := verifyHash(e, h.Sum(nil)); err != nil {
				return err
			}
			n++
			// entri dedup berbagi isi yang sama dengan sumbernya
			for _, ri := range refs[entryIndex(idx, e)] {
				_ = ri
				n++
			}
			return nil
		})
		if err != nil {
			prog.finish()
			return err
		}
		prog.add(g.RawSize)
	}
	prog.finish()
	fmt.Printf("%s %d file terverifikasi SHA-256 dalam %s — arsip sehat\n",
		okCol("✓"), n, humanDur(time.Since(started)))
	return nil
}

func entryIndex(idx *Index, target Entry) int {
	for i, e := range idx.Entries {
		if e.Name == target.Name && e.Offset == target.Offset && e.Group == target.Group && e.Ref < 0 {
			return i
		}
	}
	return -1
}

// safeJoin menolak path absolut, "..", dan apa pun yang keluar dari dest.
func safeJoin(dest, name string) (string, error) {
	if filepath.IsAbs(name) || (len(name) > 1 && name[1] == ':') {
		return "", fmt.Errorf("path absolut ditolak: %s", name)
	}
	clean := filepath.Clean("/" + filepath.FromSlash(name))
	target := filepath.Join(dest, clean)
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if absTarget != absDest && !strings.HasPrefix(absTarget, absDest+string(os.PathSeparator)) {
		return "", fmt.Errorf("path keluar dari tujuan, ditolak: %s", name)
	}
	return target, nil
}

// overwriteState mengingat keputusan prompt timpa selama satu ekstrak.
type overwriteState struct {
	all     bool
	skipped int
	reader  *bufio.Reader
}

// askOverwrite bertanya sekali per berkas (hanya di terminal interaktif).
// Mengembalikan true bila berkas boleh ditimpa. Di luar TTY: selalu true
// (perilaku lama yang diandalkan skrip).
func (s *overwriteState) askOverwrite(target string) (bool, error) {
	if !uiStdin || s.all {
		return true, nil
	}
	if _, err := os.Stat(target); err != nil {
		return true, nil // belum ada: tidak perlu bertanya
	}
	if s.reader == nil {
		s.reader = bufio.NewReader(os.Stdin)
	}
	for {
		fmt.Printf("Berkas %s sudah ada — [t]impa, [l]ewati, [s]emua timpa, [b]atal: ", target)
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return false, errors.New("dibatalkan pengguna")
		}
		switch strings.TrimSpace(strings.ToLower(line)) {
		case "t":
			return true, nil
		case "l":
			s.skipped++
			return false, nil
		case "s":
			s.all = true
			return true, nil
		case "b":
			return false, errors.New("dibatalkan pengguna")
		}
	}
}

func cmdExtract(path, dest string, password string) error {
	started := time.Now()
	idx, f, cc, err := openArchive(path, password)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	for _, e := range idx.Entries {
		if !e.Dir {
			continue
		}
		target, err := safeJoin(dest, e.Name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(target, 0o755); err != nil {
			return err
		}
	}
	refs := refsBySource(idx)
	ow := &overwriteState{}
	var totalRaw int64
	for _, g := range idx.Groups {
		totalRaw += g.RawSize
	}
	prog := newProgress("Mengekstrak", totalRaw)
	n := 0
	for _, g := range idx.Groups {
		err := processGroup(idx, f, g, cc, func(e Entry, r io.Reader) error {
			// target utama + semua target dedup yang menunjuk entri ini
			targetIdx := []int{entryIndex(idx, e)}
			targetIdx = append(targetIdx, refs[targetIdx[0]]...)
			var files []*os.File
			var targets []string
			var kept []int
			h := sha256.New()
			writers := []io.Writer{h}
			for _, ti := range targetIdx {
				te := idx.Entries[ti]
				tp, err := safeJoin(dest, te.Name)
				if err != nil {
					return err
				}
				ok, err := ow.askOverwrite(tp)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
				if err := os.MkdirAll(filepath.Dir(tp), 0o755); err != nil {
					return err
				}
				mode := os.FileMode(te.Mode)
				if mode == 0 {
					mode = 0o644
				}
				wf, err := os.OpenFile(tp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
				if err != nil {
					return err
				}
				files = append(files, wf)
				targets = append(targets, tp)
				kept = append(kept, ti)
				writers = append(writers, wf)
			}
			_, copyErr := io.Copy(io.MultiWriter(writers...), r)
			for _, wf := range files {
				wf.Close()
			}
			if copyErr != nil {
				return copyErr
			}
			if err := verifyHash(e, h.Sum(nil)); err != nil {
				return err
			}
			for i, ti := range kept {
				te := idx.Entries[ti]
				if te.ModUnix > 0 {
					t := time.Unix(0, te.ModUnix)
					_ = os.Chtimes(targets[i], t, t)
				}
				n++
			}
			return nil
		})
		if err != nil {
			prog.finish()
			return err
		}
		prog.add(g.RawSize)
	}
	prog.finish()
	skipNote := ""
	if ow.skipped > 0 {
		skipNote = fmt.Sprintf(" · %d dilewati", ow.skipped)
	}
	fmt.Printf("%s %d file diekstrak ke %s dalam %s — semua SHA-256 cocok%s\n",
		okCol("✓"), n, bold(dest), humanDur(time.Since(started)), skipNote)
	return nil
}

var _ hash.Hash
