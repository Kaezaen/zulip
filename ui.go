package main

// Lapisan UI terminal zulip (v0.6). Prinsip yang diterapkan, dari basis
// pengetahuan UI/UX Pro Max + Emil Kowalski + Anti-Slop:
//
//   - Umpan balik mengikuti lama tunggu: operasi cepat tidak menampilkan
//     apa-apa; operasi lama WAJIB punya indikator progres dengan laju
//     dan sisa waktu (kategori Feedback, severity High: "jangan biarkan
//     penantian panjang tanpa penjelasan").
//   - Setiap error membawa jalan keluar (kategori Error Recovery:
//     "sediakan langkah berikutnya yang jelas"), lihat printErrHint.
//   - Angka selalu dalam satuan manusia (MB/GB), kolom rata, info
//     sekunder diredupkan — hierarki visual, bukan dinding byte mentah.
//   - Gerak hemat (frekuensi pemakaian tinggi = animasi minimal):
//     progress diperbarui maks ~8x/detik, hanya di TTY; keluaran yang
//     di-pipe tetap teks bersih tanpa warna/bar — ramah skrip.
//   - Warna semantik dan selalu bisa dimatikan: NO_COLOR dihormati,
//     TERM=dumb dihormati. Warna tidak pernah satu-satunya pembawa arti
//     (selalu ada teks/simbol pendamping: ✓, ✗, ▸).

import (
	"fmt"
	"os"
	"strings"
	"time"
)

var (
	uiColor   bool // stdout TTY + warna diizinkan
	uiProgOut bool // stderr TTY: progress bar boleh digambar
	uiStdin   bool // stdin TTY: prompt interaktif boleh diajukan
)

func init() {
	uiColor = isTTY(os.Stdout) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	uiProgOut = isTTY(os.Stderr) && os.Getenv("TERM") != "dumb"
	uiStdin = isTTY(os.Stdin)
}

func isTTY(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

// --- warna semantik ---
func paint(code, s string) string {
	if !uiColor {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
func bold(s string) string   { return paint("1", s) }
func dim(s string) string    { return paint("2", s) }
func accent(s string) string { return paint("36", s) }
func okCol(s string) string  { return paint("32", s) }
func warnCol(s string) string { return paint("33", s) }
func errCol(s string) string { return paint("31", s) }

// humanSize memformat byte ke satuan terbaca: 123 B, 4,2 KB, 1,05 GB.
func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	val := float64(n) / float64(div)
	s := fmt.Sprintf("%.1f", val)
	if val >= 100 {
		s = fmt.Sprintf("%.0f", val)
	}
	s = strings.Replace(s, ".", ",", 1)
	if strings.HasSuffix(s, ",0") {
		s = s[:len(s)-2]
	}
	return fmt.Sprintf("%s %cB", s, "KMGTPE"[exp])
}

// humanDur memformat durasi: 320 ms, 4,7 dtk, 1 mnt 43 dtk, 2 j 5 mnt.
func humanDur(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%s dtk", strings.Replace(fmt.Sprintf("%.1f", d.Seconds()), ".", ",", 1))
	case d < time.Hour:
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		if s == 0 {
			return fmt.Sprintf("%d mnt", m)
		}
		return fmt.Sprintf("%d mnt %d dtk", m, s)
	default:
		h := int(d.Hours())
		m := int(d.Minutes()) % 60
		return fmt.Sprintf("%d j %d mnt", h, m)
	}
}

// ratioBar menggambar bar rasio kompresi selebar width karakter.
func ratioBar(pct float64, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := int(pct/100*float64(width) + 0.5)
	return accent(strings.Repeat("█", filled)) + dim(strings.Repeat("░", width-filled))
}

// --- progress bar (stderr, hanya TTY) ---

var spinFrames = []rune("⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏")

type progress struct {
	total int64
	done  int64
	label string
	start time.Time
	last  time.Time
	spin  int
	on    bool
}

func newProgress(label string, total int64) *progress {
	return &progress{total: total, label: label, start: time.Now(), on: uiProgOut}
}

func (p *progress) setLabel(label string, total int64) {
	p.label = label
	p.total = total
	p.done = 0
	p.start = time.Now()
	p.draw()
}

func (p *progress) add(n int64) {
	p.done += n
	if time.Since(p.last) < 120*time.Millisecond {
		return
	}
	p.draw()
}

func (p *progress) draw() {
	if !p.on {
		return
	}
	p.last = time.Now()
	p.spin++
	spin := string(spinFrames[p.spin%len(spinFrames)])
	elapsed := time.Since(p.start)
	rate := float64(p.done) / elapsed.Seconds()
	var line string
	if p.total > 0 {
		pct := float64(p.done) / float64(p.total) * 100
		const w = 24
		fill := int(pct / 100 * w)
		if fill > w {
			fill = w
		}
		bar := accent(strings.Repeat("█", fill)) + dim(strings.Repeat("░", w-fill))
		eta := ""
		if rate > 0 && p.done < p.total {
			eta = " · sisa ~" + humanDur(time.Duration(float64(p.total-p.done)/rate*float64(time.Second)))
		}
		line = fmt.Sprintf("%s %s  %s %5.1f%% · %s/%s · %s/dtk%s",
			spin, p.label, bar, pct, humanSize(p.done), humanSize(p.total), humanSize(int64(rate)), eta)
	} else {
		line = fmt.Sprintf("%s %s · %s · %s/dtk", spin, p.label, humanSize(p.done), humanSize(int64(rate)))
	}
	fmt.Fprintf(os.Stderr, "\r\x1b[K%s", line)
}

// finish menghapus garis progress dari layar.
func (p *progress) finish() {
	if !p.on {
		return
	}
	fmt.Fprint(os.Stderr, "\r\x1b[K")
	p.on = false
}

// printErrHint mencetak error + petunjuk pemulihan untuk kasus yang
// dikenal. Error tak dikenal dicetak apa adanya (jujur, tanpa karangan).
func printErrHint(err error) {
	fmt.Fprintln(os.Stderr, errCol("✗")+" "+err.Error())
	msg := err.Error()
	var hint string
	switch {
	case strings.Contains(msg, "kata sandi") || strings.Contains(msg, "password salah"):
		hint = "Periksa kata sandi: pakai -p<kata sandi> atau env ZYNX_PASSWORD."
	case strings.Contains(msg, "volume") && strings.Contains(msg, "hilang"):
		hint = "Pastikan semua berkas .001, .002, ... ada dalam satu folder dengan nama dasar yang sama."
	case strings.Contains(msg, "magic") || strings.Contains(msg, "bukan .zynx"):
		hint = "Berkas ini bukan arsip .zynx yang dikenali zulip."
	case strings.Contains(msg, "checksum tidak cocok"):
		hint = "Data rusak. Bila arsip dibuat dengan opsi -r, pulihkan dengan: zulip repair <arsip>"
	case strings.Contains(msg, "no such file"):
		hint = "Periksa kembali ejaan path berkas/folder sumbernya."
	case strings.Contains(msg, "dibatalkan"):
		hint = ""
	}
	if hint != "" {
		fmt.Fprintln(os.Stderr, dim("  Petunjuk: "+hint))
	}
}
