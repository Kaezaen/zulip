package main

// Recovery record ala RAR, dibangun dari Reed-Solomon (klauspost):
// arsip dipotong menjadi blok-blok; tabel CRC32 per blok menemukan blok
// yang rusak, dan blok paritas per "stripe" (maks 200 blok data, batas
// GF(2^8)) memperbaikinya. Segmen recovery menempel SETELAH footer arsip:
//
//	[CRC table: dataBlocks x u32][paritas stripe 0][paritas stripe 1]...
//	[Trailer 32B: coveredLen u64][blockSize u32][dataBlocks u32]
//	              [stripeData u32][pct u32][magic "ZYNXREC\x1a"]
//
// coveredLen = panjang arsip sebelum segmen recovery (footer termasuk).
// Reader biasa mengabaikan segmen ini (view dibatasi ke coveredLen);
// perintah `repair` yang memakainya. Bekerja juga untuk arsip terenkripsi
// (yang dipulihkan byte ciphertext-nya) dan di dalam SFX.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"

	"github.com/klauspost/reedsolomon"
)

var recoveryMagic = []byte{'Z', 'Y', 'N', 'X', 'R', 'E', 'C', 0x1a}

const (
	recoveryTrailerSize = 32
	stripeDataBlocks    = 200
)

type recoveryInfo struct {
	CoveredLen int64
	BlockSize  int
	DataBlocks int
	StripeData int
	Pct        int
}

func (r *recoveryInfo) parityPerStripe(dataInStripe int) int {
	p := (dataInStripe*r.Pct + 99) / 100
	if p < 1 {
		p = 1
	}
	return p
}

func (r *recoveryInfo) stripes() int {
	return (r.DataBlocks + r.StripeData - 1) / r.StripeData
}

func (r *recoveryInfo) parityTotal() int64 {
	var total int64
	for s := 0; s < r.stripes(); s++ {
		n := r.StripeData
		if rem := r.DataBlocks - s*r.StripeData; rem < n {
			n = rem
		}
		total += int64(r.parityPerStripe(n)) * int64(r.BlockSize)
	}
	return total
}

func (r *recoveryInfo) segmentSize() int64 {
	return int64(r.DataBlocks)*4 + r.parityTotal() + recoveryTrailerSize
}

// detectRecovery membaca trailer di akhir wilayah arsip [0, arcEnd).
func detectRecovery(rd io.ReaderAt, arcEnd int64) *recoveryInfo {
	if arcEnd < recoveryTrailerSize {
		return nil
	}
	t := make([]byte, recoveryTrailerSize)
	if _, err := rd.ReadAt(t, arcEnd-recoveryTrailerSize); err != nil {
		return nil
	}
	for i, b := range recoveryMagic {
		if t[24+i] != b {
			return nil
		}
	}
	info := &recoveryInfo{
		CoveredLen: int64(binary.LittleEndian.Uint64(t[0:8])),
		BlockSize:  int(binary.LittleEndian.Uint32(t[8:12])),
		DataBlocks: int(binary.LittleEndian.Uint32(t[12:16])),
		StripeData: int(binary.LittleEndian.Uint32(t[16:20])),
		Pct:        int(binary.LittleEndian.Uint32(t[20:24])),
	}
	if info.CoveredLen <= 0 || info.BlockSize < 512 || info.BlockSize > 1<<26 ||
		info.DataBlocks <= 0 || info.StripeData <= 0 || info.StripeData > 100000 ||
		info.Pct < 1 || info.Pct > 100 || info.CoveredLen >= arcEnd {
		return nil
	}
	// Jumlah blok harus konsisten dengan panjang wilayah tercakup —
	// tanpa ini trailer rusak bisa membuat loop stripe raksasa.
	if int64(info.DataBlocks) != (info.CoveredLen+int64(info.BlockSize)-1)/int64(info.BlockSize) {
		return nil
	}
	if arcEnd-info.CoveredLen != info.segmentSize() {
		return nil
	}
	return info
}

// addRecoveryRecord menghitung & menempelkan segmen recovery ke file arsip
// yang baru selesai ditulis (file tunggal; bukan volume).
func addRecoveryRecord(path string, pct int) error {
	if pct < 1 || pct > 50 {
		return errors.New("persen recovery harus 1..50")
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	covered := st.Size()
	blockSize := 4096
	if covered > 32<<20 {
		blockSize = 16384
	}
	info := &recoveryInfo{
		CoveredLen: covered,
		BlockSize:  blockSize,
		DataBlocks: int((covered + int64(blockSize) - 1) / int64(blockSize)),
		StripeData: stripeDataBlocks,
		Pct:        pct,
	}
	crcTable := make([]byte, 0, info.DataBlocks*4)
	var parities [][]byte
	buf := make([]byte, blockSize)
	for s := 0; s < info.stripes(); s++ {
		start := s * info.StripeData
		n := info.StripeData
		if rem := info.DataBlocks - start; rem < n {
			n = rem
		}
		p := info.parityPerStripe(n)
		enc, err := reedsolomon.New(n, p)
		if err != nil {
			return err
		}
		shards := make([][]byte, n+p)
		for i := 0; i < n; i++ {
			blk := make([]byte, blockSize)
			off := int64(start+i) * int64(blockSize)
			nn, _ := f.ReadAt(buf, off)
			copy(blk, buf[:nn])
			shards[i] = blk
			var cb [4]byte
			// CRC atas byte ASLI blok (blok terakhir: hanya byte yang ada)
			binary.LittleEndian.PutUint32(cb[:], crc32.ChecksumIEEE(buf[:nn]))
			crcTable = append(crcTable, cb[:]...)
		}
		for i := n; i < n+p; i++ {
			shards[i] = make([]byte, blockSize)
		}
		if err := enc.Encode(shards); err != nil {
			return err
		}
		parities = append(parities, shards[n:]...)
	}
	if _, err := f.WriteAt(crcTable, covered); err != nil {
		return err
	}
	pos := covered + int64(len(crcTable))
	for _, pb := range parities {
		if _, err := f.WriteAt(pb, pos); err != nil {
			return err
		}
		pos += int64(len(pb))
	}
	t := make([]byte, recoveryTrailerSize)
	binary.LittleEndian.PutUint64(t[0:8], uint64(info.CoveredLen))
	binary.LittleEndian.PutUint32(t[8:12], uint32(info.BlockSize))
	binary.LittleEndian.PutUint32(t[12:16], uint32(info.DataBlocks))
	binary.LittleEndian.PutUint32(t[16:20], uint32(info.StripeData))
	binary.LittleEndian.PutUint32(t[20:24], uint32(info.Pct))
	copy(t[24:], recoveryMagic)
	if _, err := f.WriteAt(t, pos); err != nil {
		return err
	}
	return nil
}

// cmdRepair memindai blok yang CRC-nya tidak cocok dan merekonstruksinya
// dari paritas Reed-Solomon, menulis kembali hanya blok yang rusak.
func cmdRepair(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	// Wilayah arsip: perhitungkan stub SFX di depan & trailer SFX di belakang.
	base := int64(0)
	arcEnd := st.Size()
	if arcEnd >= 16 {
		tail := make([]byte, 16)
		if _, err := f.ReadAt(tail, arcEnd-16); err == nil {
			isSFX := true
			for i, b := range sfxTrailerMagic {
				if tail[8+i] != b {
					isSFX = false
					break
				}
			}
			if isSFX {
				base = int64(binary.LittleEndian.Uint64(tail[0:8]))
				arcEnd -= 16
			}
		}
	}
	// Untuk volume tidak didukung.
	hdr := make([]byte, 8)
	if _, err := f.ReadAt(hdr, base); err == nil {
		isVol := true
		for i, b := range volumeMagic {
			if hdr[i] != b {
				isVol = false
				break
			}
		}
		if isVol {
			return errors.New("repair belum mendukung arsip multi-volume")
		}
	}
	// detectRecovery mengharapkan ReaderAt dengan offset wilayah arsip.
	view := io.NewSectionReader(f, base, arcEnd-base)
	info := detectRecovery(view, arcEnd-base)
	if info == nil {
		return errors.New("arsip tidak memiliki recovery record")
	}
	segStart := info.CoveredLen
	crcTable := make([]byte, info.DataBlocks*4)
	if _, err := view.ReadAt(crcTable, segStart); err != nil {
		return err
	}
	parityStart := segStart + int64(len(crcTable))
	bs := info.BlockSize
	// Pindai blok rusak.
	bad := map[int]bool{}
	buf := make([]byte, bs)
	for i := 0; i < info.DataBlocks; i++ {
		off := int64(i) * int64(bs)
		want := int64(bs)
		if rem := info.CoveredLen - off; rem < want {
			want = rem
		}
		n, _ := view.ReadAt(buf[:want], off)
		if int64(n) != want {
			bad[i] = true
			continue
		}
		if crc32.ChecksumIEEE(buf[:n]) != binary.LittleEndian.Uint32(crcTable[i*4:]) {
			bad[i] = true
		}
	}
	if len(bad) == 0 {
		fmt.Printf("OK: %d blok diperiksa, tidak ada yang rusak (recovery %d%% siap pakai)\n", info.DataBlocks, info.Pct)
		return nil
	}
	fmt.Printf("ditemukan %d blok rusak dari %d, memperbaiki...\n", len(bad), info.DataBlocks)
	// Perbaiki per stripe.
	parityOff := parityStart
	fixed := 0
	for s := 0; s < info.stripes(); s++ {
		start := s * info.StripeData
		n := info.StripeData
		if rem := info.DataBlocks - start; rem < n {
			n = rem
		}
		p := info.parityPerStripe(n)
		var badInStripe []int
		for i := start; i < start+n; i++ {
			if bad[i] {
				badInStripe = append(badInStripe, i)
			}
		}
		if len(badInStripe) > p {
			return fmt.Errorf("stripe %d: %d blok rusak melebihi paritas %d — tidak bisa diperbaiki", s, len(badInStripe), p)
		}
		if len(badInStripe) > 0 {
			enc, err := reedsolomon.New(n, p)
			if err != nil {
				return err
			}
			shards := make([][]byte, n+p)
			for i := 0; i < n; i++ {
				if bad[start+i] {
					continue // nil = erasure untuk Reconstruct
				}
				blk := make([]byte, bs)
				want := int64(bs)
				if rem := info.CoveredLen - int64(start+i)*int64(bs); rem < want {
					want = rem
				}
				nn, _ := view.ReadAt(blk[:want], int64(start+i)*int64(bs))
				blk = blk[:bs]
				_ = nn
				shards[i] = blk
			}
			for j := 0; j < p; j++ {
				pb := make([]byte, bs)
				if _, err := view.ReadAt(pb, parityOff+int64(j)*int64(bs)); err != nil {
					return err
				}
				shards[n+j] = pb
			}
			if err := enc.Reconstruct(shards); err != nil {
				return fmt.Errorf("stripe %d: rekonstruksi gagal: %w", s, err)
			}
			for _, bi := range badInStripe {
				off := base + int64(bi)*int64(bs)
				want := int64(bs)
				if rem := info.CoveredLen - int64(bi)*int64(bs); rem < want {
					want = rem
				}
				if _, err := f.WriteAt(shards[bi-start][:want], off); err != nil {
					return err
				}
				fixed++
			}
		}
		parityOff += int64(p) * int64(bs)
	}
	// Verifikasi ulang semua blok yang tadi rusak.
	for bi := range bad {
		off := int64(bi) * int64(bs)
		want := int64(bs)
		if rem := info.CoveredLen - off; rem < want {
			want = rem
		}
		n, _ := view.ReadAt(buf[:want], off)
		if int64(n) != want || crc32.ChecksumIEEE(buf[:n]) != binary.LittleEndian.Uint32(crcTable[bi*4:]) {
			return fmt.Errorf("blok %d masih rusak setelah repair", bi)
		}
	}
	fmt.Printf("selesai: %d blok diperbaiki dari paritas Reed-Solomon, arsip pulih\n", fixed)
	return nil
}
