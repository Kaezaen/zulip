// zulip-gui — antarmuka grafis Windows untuk pengarsip .zynx (zulip).
//
// Jendela native Win32 (lxn/walk, tanpa CGO) yang menjalankan mesin
// zulip.exe di sampingnya. Dibangun untuk rasa WinRAR: buka arsip ->
// lihat daftar isi -> ekstrak; atau kumpulkan berkas -> buat arsip.
// Mode baris perintah untuk integrasi Explorer:
//   zulip-gui.exe --open <arsip.zynx>     (klik ganda pada .zynx)
//   zulip-gui.exe --extract <arsip.zynx>  (menu klik kanan "Ekstrak...")
//   zulip-gui.exe --add <file/folder>     (menu klik kanan "Kompres...")
package main

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/json"
	"image/png"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/lxn/walk"
	. "github.com/lxn/walk/declarative"
)

const guiVersion = "0.8.0"

// ---------- util ----------

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

func cliPath() string {
	exe, err := os.Executable()
	if err == nil {
		p := filepath.Join(filepath.Dir(exe), "zulip.exe")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "zulip.exe" // berharap ada di PATH
}

// runCapture menjalankan CLI dan menangkap stdout/stderr terpisah.
func runCapture(args ...string) (string, string, error) {
	cmd := exec.Command(cliPath(), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

// ---------- model arsip ----------

type jEntry struct {
	Name  string `json:"name"`
	Size  int64  `json:"size"`
	Dir   bool   `json:"dir"`
	Mod   int64  `json:"mod_unix_nano"`
	Dedup bool   `json:"dedup"`
}
type jGroup struct {
	Key   string `json:"key"`
	Codec string `json:"codec"`
	Raw   int64  `json:"raw"`
	Comp  int64  `json:"comp"`
}
type jArchive struct {
	Version   int      `json:"version"`
	Mode      string   `json:"mode"`
	Encrypted bool     `json:"encrypted"`
	Entries   []jEntry `json:"entries"`
	Groups    []jGroup `json:"groups"`
}

type entryModel struct {
	walk.TableModelBase
	items []jEntry
}

func (m *entryModel) RowCount() int { return len(m.items) }

func (m *entryModel) Value(row, col int) interface{} {
	e := m.items[row]
	switch col {
	case 0:
		return e.Name
	case 1:
		if e.Dir {
			return ""
		}
		return humanSize(e.Size)
	case 2:
		if e.Mod > 0 {
			return time.Unix(0, e.Mod).Format("2006-01-02 15:04")
		}
		return "-"
	case 3:
		if e.Dir {
			return "Folder"
		}
		if e.Dedup {
			return "Duplikat (dedup)"
		}
		return ""
	}
	return ""
}

// ---------- keadaan aplikasi ----------

type app struct {
	logoView *walk.ImageView
	mw        *walk.MainWindow
	table     *walk.TableView
	status    *walk.Label
	pathLabel *walk.Label
	model     *entryModel
	archive   string // arsip yang sedang dibuka ("" = belum ada)
	password  string // kata sandi sesi untuk arsip terbuka
	data      *jArchive
}

func (a *app) setStatus(s string) {
	if a.status != nil {
		a.status.SetText(s)
	}
}

// loadArchive membaca daftar isi lewat CLI (mode JSON) dan mengisi tabel.
func (a *app) loadArchive(path string) {
	args := []string{"l", "--json"}
	pw := a.password
	if pw != "" {
		args = append(args, "-p"+pw)
	}
	args = append(args, path)
	out, serr, err := runCapture(args...)
	if err != nil && pw == "" && (strings.Contains(serr, "kata sandi") || strings.Contains(serr, "password")) {
		// Arsip terenkripsi: minta kata sandi, coba sekali lagi.
		if p, ok := askPassword(a.mw, "Arsip ini terenkripsi. Masukkan kata sandi:"); ok {
			a.password = p
			a.loadArchive(path)
			return
		}
		a.setStatus("Arsip terenkripsi — kata sandi diperlukan.")
		return
	}
	if err != nil {
		walk.MsgBox(a.mw, "Gagal membuka arsip", strings.TrimSpace(serr), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	var ja jArchive
	if err := json.Unmarshal([]byte(out), &ja); err != nil {
		walk.MsgBox(a.mw, "Gagal membaca daftar isi", err.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	sort.Slice(ja.Entries, func(i, j int) bool { return ja.Entries[i].Name < ja.Entries[j].Name })
	a.archive = path
	a.data = &ja
	a.model.items = ja.Entries
	a.model.PublishRowsReset()
	var totalRaw, totalComp int64
	for _, e := range ja.Entries {
		totalRaw += e.Size
	}
	for _, g := range ja.Groups {
		totalComp += g.Comp
	}
	a.pathLabel.SetText(path)
	enc := ""
	if ja.Encrypted {
		enc = " · terenkripsi"
	}
	a.setStatus(fmt.Sprintf("%d entri · asli %s · terkompresi %s · mode %s%s",
		len(ja.Entries), humanSize(totalRaw), humanSize(totalComp), ja.Mode, enc))
	a.mw.SetTitle("zulip — " + filepath.Base(path))
}

// ---------- dialog kata sandi ----------

func askPassword(owner walk.Form, prompt string) (string, bool) {
	var dlg *walk.Dialog
	var le *walk.LineEdit
	accepted := false
	result := ""
	Dialog{
		AssignTo: &dlg,
		Title:    "Kata sandi",
		MinSize:  Size{Width: 340, Height: 130},
		Layout:   VBox{},
		Children: []Widget{
			Label{Text: prompt},
			LineEdit{AssignTo: &le, PasswordMode: true},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{Text: "Buka", OnClicked: func() { result = le.Text(); accepted = true; dlg.Accept() }},
					PushButton{Text: "Batal", OnClicked: func() { dlg.Cancel() }},
				},
			},
		},
	}.Create(owner)
	setFormIcon(dlg)
	dlg.Run()
	if !accepted {
		return "", false
	}
	return result, true
}

// ---------- dialog progres (menjalankan CLI) ----------

// runWithProgress menjalankan perintah CLI sambil menampilkan log
// langsung dan bar progres berputar. Mengembalikan error + keluaran.
func runWithProgress(owner walk.Form, title string, args ...string) (string, error) {
	var dlg *walk.Dialog
	var logEdit *walk.TextEdit
	var cancelBtn *walk.PushButton
	var output bytes.Buffer
	finished := false
	var runErr error

	cmd := exec.Command(cliPath(), args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	cmd.Stderr = cmd.Stdout

	Dialog{
		AssignTo: &dlg,
		Title:    title,
		MinSize:  Size{Width: 560, Height: 340},
		Layout:   VBox{},
		Children: []Widget{
			ProgressBar{MarqueeMode: true},
			TextEdit{AssignTo: &logEdit, ReadOnly: true, VScroll: true},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{
						AssignTo: &cancelBtn,
						Text:     "Batalkan",
						OnClicked: func() {
							if finished {
								dlg.Close(walk.DlgCmdCancel)
								return
							}
							if cmd.Process != nil {
								cmd.Process.Kill()
							}
						},
					},
				},
			},
		},
	}.Create(owner)
	setFormIcon(dlg)

	go func() {
		if err := cmd.Start(); err != nil {
			runErr = err
		} else {
			sc := bufio.NewScanner(stdout)
			sc.Buffer(make([]byte, 1024*1024), 1024*1024)
			for sc.Scan() {
				line := sc.Text()
				output.WriteString(line + "\n")
				dlg.Synchronize(func() {
					logEdit.AppendText(line + "\r\n")
				})
			}
			runErr = cmd.Wait()
		}
		dlg.Synchronize(func() {
			finished = true
			if runErr != nil {
				logEdit.AppendText("\r\n[gagal] " + runErr.Error() + "\r\n")
				cancelBtn.SetText("Tutup")
			} else {
				dlg.Accept()
			}
		})
	}()
	dlg.Run()
	// Dialog ditutup saat proses masih berjalan -> hentikan prosesnya.
	if !finished && cmd.Process != nil {
		cmd.Process.Kill()
		if runErr == nil {
			runErr = fmt.Errorf("dibatalkan pengguna")
		}
	}
	return output.String(), runErr
}

// quickAdd mengompres satu berkas/folder LANGSUNG ke .zynx di
// sampingnya (mode Ultra), hanya menampilkan jendela progres — persis
// perilaku "Add to <nama>.rar" milik WinRAR dari menu klik kanan.
func (a *app) quickAdd(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		walk.MsgBox(a.mw, "Kompres", "Berkas/folder tidak ditemukan:\r\n"+path, walk.MsgBoxOK|walk.MsgBoxIconError)
		return true
	}
	var arc string
	if info.IsDir() {
		arc = filepath.Join(filepath.Dir(path), filepath.Base(path)+".zynx")
	} else {
		arc = strings.TrimSuffix(path, filepath.Ext(path)) + ".zynx"
		if arc == path {
			arc = path + ".zynx"
		}
	}
	out, err := runWithProgress(a.mw, "Mengompres…", "a", "-m3", arc, path)
	if err != nil {
		walk.MsgBox(a.mw, "Kompres gagal", tailLines(out, 6), walk.MsgBoxOK|walk.MsgBoxIconError)
		return true
	}
	// Tunjukkan hasilnya di Explorer.
	exec.Command("explorer.exe", "/select,", arc).Start()
	return true
}

// extractHere mengekstrak arsip ke folder senama di sampingnya, hanya
// dengan jendela progres. Arsip terenkripsi dialihkan ke dialog penuh.
func (a *app) extractHere(archive string) bool {
	base := strings.TrimSuffix(filepath.Base(archive), filepath.Ext(archive))
	dest := filepath.Join(filepath.Dir(archive), base)
	out, err := runWithProgress(a.mw, "Mengekstrak…", "x", archive, dest)
	if err != nil {
		if strings.Contains(out, "kata sandi") || strings.Contains(out, "password") {
			a.loadArchive(archive)
			a.showExtract()
			return false // dialihkan ke dialog: jendela tetap hidup
		}
		walk.MsgBox(a.mw, "Ekstrak gagal", tailLines(out, 6), walk.MsgBoxOK|walk.MsgBoxIconError)
		return true
	}
	exec.Command("explorer.exe", dest).Start()
	return true
}

// quickSFX membuat SFX .exe langsung di samping berkas/folder —
// untuk dibagikan ke orang yang tidak memasang zulip.
func (a *app) quickSFX(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		walk.MsgBox(a.mw, "Buat SFX", "Berkas/folder tidak ditemukan:\r\n"+path, walk.MsgBoxOK|walk.MsgBoxIconError)
		return true
	}
	var out string
	if info.IsDir() {
		out = filepath.Join(filepath.Dir(path), filepath.Base(path)+".exe")
	} else {
		out = strings.TrimSuffix(path, filepath.Ext(path)) + ".exe"
		if out == path {
			out = path + ".exe"
		}
	}
	o, err := runWithProgress(a.mw, "Membuat SFX…", "a", "-m3", "--sfx", out, path)
	if err != nil {
		walk.MsgBox(a.mw, "Buat SFX gagal", tailLines(o, 6), walk.MsgBoxOK|walk.MsgBoxIconError)
		return true
	}
	exec.Command("explorer.exe", "/select,", out).Start()
	return true
}

// wrapSFXof membungkus arsip terbuka/tertentu menjadi SFX .exe.
func (a *app) wrapSFXof(archive string) bool {
	out := strings.TrimSuffix(archive, filepath.Ext(archive)) + ".exe"
	o, err := runWithProgress(a.mw, "Membuat SFX…", "sfx", archive, out)
	if err != nil {
		walk.MsgBox(a.mw, "Buat SFX gagal", tailLines(o, 6), walk.MsgBoxOK|walk.MsgBoxIconError)
		return true
	}
	exec.Command("explorer.exe", "/select,", out).Start()
	return true
}

// toZipOf mengonversi arsip menjadi .zip standar yang universal.
func (a *app) toZipOf(archive string) bool {
	out := strings.TrimSuffix(archive, filepath.Ext(archive)) + ".zip"
	args := []string{"tozip"}
	if a.password != "" {
		args = append(args, "-p"+a.password)
	}
	args = append(args, archive, out)
	o, err := runWithProgress(a.mw, "Mengonversi ke ZIP…", args...)
	if err != nil {
		walk.MsgBox(a.mw, "Konversi gagal", tailLines(o, 6), walk.MsgBoxOK|walk.MsgBoxIconError)
		return true
	}
	exec.Command("explorer.exe", "/select,", out).Start()
	return true
}

// ---------- dialog ekstrak ----------

func (a *app) showExtract() {
	if a.archive == "" {
		walk.MsgBox(a.mw, "Ekstrak", "Buka dulu arsip .zynx yang mau diekstrak.", walk.MsgBoxOK|walk.MsgBoxIconInformation)
		return
	}
	base := filepath.Base(a.archive)
	name := strings.TrimSuffix(base, filepath.Ext(base))
	defaultDest := filepath.Join(filepath.Dir(a.archive), name)

	var dlg *walk.Dialog
	var destEdit *walk.LineEdit
	var pwEdit *walk.LineEdit
	snapDest, snapPw := "", ""
	d := Dialog{
		AssignTo: &dlg,
		Title:    "Ekstrak arsip",
		MinSize:  Size{Width: 520, Height: 220},
		Layout:   VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
		Children: []Widget{
			Label{Text: "Arsip: " + a.archive},
			Label{Text: "Folder tujuan:"},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					LineEdit{AssignTo: &destEdit, Text: defaultDest},
					PushButton{Text: "Telusuri…", OnClicked: func() {
						fd := new(walk.FileDialog)
						fd.Title = "Pilih folder tujuan"
						if ok, _ := fd.ShowBrowseFolder(dlg); ok {
							destEdit.SetText(fd.FilePath)
						}
					}},
				},
			},
			Label{Text: "Kata sandi (bila arsip terenkripsi):"},
			LineEdit{AssignTo: &pwEdit, PasswordMode: true, Text: a.password},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{Text: "Ekstrak", OnClicked: func() { snapDest, snapPw = destEdit.Text(), pwEdit.Text(); dlg.Accept() }},
					PushButton{Text: "Batal", OnClicked: func() { dlg.Cancel() }},
				},
			},
		},
	}
	d.Create(a.mw)
	setFormIcon(dlg)
	res := dlg.Run()
	if res != walk.DlgCmdOK {
		return
	}
	dest := snapDest
	args := []string{"x"}
	if pw := snapPw; pw != "" {
		args = append(args, "-p"+pw)
	}
	args = append(args, a.archive, dest)
	out, err := runWithProgress(a.mw, "Mengekstrak…", args...)
	if err != nil {
		walk.MsgBox(a.mw, "Ekstrak gagal", tailLines(out, 6), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	if walk.MsgBox(a.mw, "Ekstrak selesai", "Arsip berhasil diekstrak ke:\r\n"+dest+"\r\n\r\nBuka folder hasil sekarang?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
		exec.Command("explorer.exe", dest).Start()
	}
}

func tailLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\r\n")
}

// ---------- dialog buat arsip ----------

func (a *app) showAdd(initial []string) {
	inputs := append([]string{}, initial...)
	var dlg *walk.Dialog
	var listBox *walk.ListBox
	var arcEdit *walk.LineEdit
	var modeBox *walk.ComboBox
	var pwEdit *walk.LineEdit
	var recEdit *walk.NumberEdit
	var volEdit *walk.LineEdit
	var sfxCheck *walk.CheckBox

	refreshList := func() {
		listBox.SetModel(inputs)
	}
	// Nilai dialog disalin ke sini oleh tombol "Buat arsip" SEBELUM
	// dialog ditutup — kontrol walk dibuang saat Run() kembali, jadi
	// membaca .Text() sesudahnya menghasilkan string kosong (bug yang
	// dilaporkan dari uji device: "Nama arsip tujuan belum diisi"
	// padahal kolomnya terisi).
	var snap struct {
		inputs []string
		arc    string
		mode   int
		pw     string
		rec    int
		vol    string
		sfx    bool
	}
	defaultArc := ""
	if len(initial) == 1 {
		base := filepath.Base(filepath.Clean(initial[0]))
		defaultArc = filepath.Join(filepath.Dir(initial[0]), base+".zynx")
	}
	d := Dialog{
		AssignTo: &dlg,
		Title:    "Buat arsip .zynx",
		MinSize:  Size{Width: 640, Height: 500},
		Layout:   VBox{Margins: Margins{Left: 10, Top: 10, Right: 10, Bottom: 10}},
		Children: []Widget{
			Label{Text: "Berkas dan folder yang diarsipkan:"},
			ListBox{AssignTo: &listBox, Model: inputs, MinSize: Size{Height: 110}},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					PushButton{Text: "Tambah berkas…", OnClicked: func() {
						fd := new(walk.FileDialog)
						fd.Title = "Pilih berkas"
						fd.Filter = "Semua berkas (*.*)|*.*"
						if ok, _ := fd.ShowOpenMultiple(dlg); ok {
							inputs = append(inputs, fd.FilePaths...)
							refreshList()
						}
					}},
					PushButton{Text: "Tambah folder…", OnClicked: func() {
						fd := new(walk.FileDialog)
						fd.Title = "Pilih folder"
						if ok, _ := fd.ShowBrowseFolder(dlg); ok {
							inputs = append(inputs, fd.FilePath)
							refreshList()
						}
					}},
					PushButton{Text: "Hapus pilihan", OnClicked: func() {
						i := listBox.CurrentIndex()
						if i >= 0 && i < len(inputs) {
							inputs = append(inputs[:i], inputs[i+1:]...)
							refreshList()
						}
					}},
					HSpacer{},
				},
			},
			Label{Text: "Simpan arsip sebagai:"},
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					LineEdit{AssignTo: &arcEdit, Text: defaultArc},
					PushButton{Text: "Telusuri…", OnClicked: func() {
						fd := new(walk.FileDialog)
						fd.Title = "Simpan arsip"
						fd.Filter = "Arsip zulip (*.zynx)|*.zynx"
						if ok, _ := fd.ShowSave(dlg); ok {
							p := fd.FilePath
							if !strings.HasSuffix(strings.ToLower(p), ".zynx") {
								p += ".zynx"
							}
							arcEdit.SetText(p)
						}
					}},
				},
			},
			GroupBox{
				Title:  "Opsi kompresi",
				Layout: Grid{Columns: 4},
				Children: []Widget{
					Label{Text: "Mode kompresi:"},
					ComboBox{AssignTo: &modeBox, Model: []string{"Cepat", "Normal", "Ultra (terkecil)"}, CurrentIndex: 2},
					Label{Text: "Recovery % (0-50):"},
					NumberEdit{AssignTo: &recEdit, MinValue: 0, MaxValue: 50, Decimals: 0},
					Label{Text: "Kata sandi (opsional):"},
					LineEdit{AssignTo: &pwEdit, PasswordMode: true},
					Label{Text: "Volume (mis. 10m):"},
					LineEdit{AssignTo: &volEdit},
				},
			},
			CheckBox{AssignTo: &sfxCheck, Text: "Bungkus sebagai SFX (.exe — penerima bisa ekstrak TANPA zulip)"},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{Text: "Buat arsip", OnClicked: func() {
						snap.inputs = append([]string{}, inputs...)
						snap.arc = arcEdit.Text()
						snap.mode = modeBox.CurrentIndex()
						snap.pw = pwEdit.Text()
						snap.rec = int(recEdit.Value())
						snap.vol = volEdit.Text()
						snap.sfx = sfxCheck.Checked()
						dlg.Accept()
					}},
					PushButton{Text: "Batal", OnClicked: func() { dlg.Cancel() }},
				},
			},
		},
	}
	d.Create(a.mw)
	setFormIcon(dlg)
	res := dlg.Run()
	if res != walk.DlgCmdOK {
		return
	}
	inputs = snap.inputs
	if len(inputs) == 0 {
		walk.MsgBox(a.mw, "Buat arsip", "Belum ada berkas/folder yang dipilih.", walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	arc := snap.arc
	if arc == "" {
		walk.MsgBox(a.mw, "Buat arsip", "Nama arsip tujuan belum diisi.", walk.MsgBoxOK|walk.MsgBoxIconWarning)
		return
	}
	sfx := snap.sfx
	if sfx {
		if !strings.HasSuffix(strings.ToLower(arc), ".exe") {
			arc = strings.TrimSuffix(arc, filepath.Ext(arc)) + ".exe"
		}
	} else if !strings.HasSuffix(strings.ToLower(arc), ".zynx") {
		arc += ".zynx"
	}
	if _, err := os.Stat(arc); err == nil {
		if walk.MsgBox(a.mw, "Timpa arsip?", "Arsip "+arc+" sudah ada.\r\nTimpa dengan yang baru?", walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
			return
		}
	}
	modeFlag := []string{"-m1", "-m3", "-m5"}[snap.mode]
	args := []string{"a", modeFlag}
	if pw := snap.pw; pw != "" {
		args = append(args, "-p"+pw)
	}
	if rec := snap.rec; rec > 0 {
		args = append(args, fmt.Sprintf("-r%d", rec))
	}
	if vol := strings.TrimSpace(snap.vol); vol != "" {
		args = append(args, "-v"+vol)
	}
	if sfx {
		args = append(args, "--sfx")
	}
	args = append(args, arc)
	args = append(args, inputs...)
	out, err := runWithProgress(a.mw, "Membuat arsip…", args...)
	if err != nil {
		walk.MsgBox(a.mw, "Pembuatan gagal", tailLines(out, 6), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	if !sfx {
		a.loadArchive(arc)
	} else {
		walk.MsgBox(a.mw, "Selesai", "SFX dibuat: "+arc, walk.MsgBoxOK|walk.MsgBoxIconInformation)
	}
}

// ---------- jendela utama ----------

func (a *app) openArchiveDialog() {
	fd := new(walk.FileDialog)
	fd.Title = "Buka arsip zulip"
	fd.Filter = "Arsip zulip (*.zynx)|*.zynx|Semua berkas (*.*)|*.*"
	if ok, _ := fd.ShowOpen(a.mw); ok {
		a.password = ""
		a.loadArchive(fd.FilePath)
	}
}

func (a *app) runSimple(title string, args ...string) {
	out, err := runWithProgress(a.mw, title, args...)
	if err != nil {
		walk.MsgBox(a.mw, title, tailLines(out, 6), walk.MsgBoxOK|walk.MsgBoxIconError)
		return
	}
	walk.MsgBox(a.mw, title, tailLines(out, 3), walk.MsgBoxOK|walk.MsgBoxIconInformation)
}

// catPNG adalah logo kucing yang sama dengan ikon berkas .exe.
//
//go:embed cat.png
var catPNG []byte

//go:embed cat48.png
var cat48PNG []byte

//go:embed cat64.png
var cat64PNG []byte

// appIcon dibangun sekali di main() dari PNG tertanam; dipakai semua
// jendela & dialog. Pemuatan ikon TIDAK BOLEH menggagalkan start:
// kegagalan apa pun (termasuk perilaku walk di lingkungan tertentu —
// uji Wine menemukan NewIconFromResourceId membunuh proses) ditelan.
var appIcon *walk.Icon


func buildAppIcon() {
	defer func() { _ = recover() }()
	img, err := png.Decode(bytes.NewReader(catPNG))
	if err != nil {
		return
	}
	if icon, err := walk.NewIconFromImage(img); err == nil {
		appIcon = icon
	}
}

func setFormIcon(f walk.Form) {
	defer func() { _ = recover() }()
	if appIcon != nil && f != nil {
		f.SetIcon(appIcon)
	}
}

func catBitmap(data []byte) *walk.Bitmap {
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	bmp, err := walk.NewBitmapFromImage(img)
	if err != nil {
		return nil
	}
	return bmp
}

func dbglog(s string) {
	f, err := os.OpenFile(filepath.Join(filepath.Dir(os.Args[0]), "gui-debug.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(s + "\n")
}

// showAbout menampilkan dialog tentang berlogo.
func (a *app) showAbout() {
	v, _, _ := runCapture("version")
	var dlg *walk.Dialog
	var logo *walk.ImageView
	d := Dialog{
		AssignTo: &dlg,
		Title:    "Tentang zulip",
		MinSize:  Size{Width: 380, Height: 210},
		Layout:   VBox{Margins: Margins{Left: 14, Top: 14, Right: 14, Bottom: 14}},
		Children: []Widget{
			Composite{
				Layout: HBox{MarginsZero: true},
				Children: []Widget{
					ImageView{AssignTo: &logo},
					Composite{
						Layout: VBox{MarginsZero: true, SpacingZero: true},
						Children: []Widget{
							Label{Text: "zulip " + guiVersion, Font: Font{Family: "Segoe UI", PointSize: 13, Bold: true}},
							Label{Text: "Mesin: " + strings.TrimSpace(v)},
							Label{Text: "Format arsip .zynx (format v5)"},
						},
					},
				},
			},
			Label{Text: "Kompresi maksimum: Zstd / LZMA2 / Brotli + filter BCJ2,\r\nDelta, dan REP-lite. Enkripsi AES-256-GCM + Argon2id,\r\nrecovery Reed-Solomon, multi-volume, SFX, dan ekspor ZIP."},
			Composite{
				Layout: HBox{},
				Children: []Widget{
					HSpacer{},
					PushButton{Text: "OK", OnClicked: func() { dlg.Accept() }},
				},
			},
		},
	}
	d.Create(a.mw)
	setFormIcon(dlg)
	if logo != nil {
		if bmp := catBitmap(cat64PNG); bmp != nil {
			logo.SetImage(bmp)
		}
	}
	dlg.Run()
}

func main() {
	// Penjaga crash terakhir: catat & tampilkan, jangan mati senyap.
	defer func() {
		if r := recover(); r != nil {
			dbglog(fmt.Sprintf("PANIC: %v", r))
		}
	}()
	dbglog("start")
	buildAppIcon()
	a := &app{model: &entryModel{}}

	var startup func()
	args := os.Args[1:]
	if len(args) >= 2 {
		switch args[0] {
		case "--open":
			p := args[1]
			startup = func() { a.loadArchive(p) }
		case "--extract":
			p := args[1]
			startup = func() { a.loadArchive(p); a.showExtract() }
		case "--add":
			p := args[1]
			startup = func() { a.showAdd([]string{p}) }
		case "--quicksfx":
			p := args[1]
			startup = func() { if a.quickSFX(p) { a.mw.Close() } }
		case "--tosfx":
			p := args[1]
			startup = func() { if a.wrapSFXof(p) { a.mw.Close() } }
		case "--tozip":
			p := args[1]
			startup = func() { if a.toZipOf(p) { a.mw.Close() } }
		case "--quickadd":
			p := args[1]
			startup = func() { if a.quickAdd(p) { a.mw.Close() } }
		case "--extracthere":
			p := args[1]
			startup = func() { if a.extractHere(p) { a.mw.Close() } }
		case "--test":
			p := args[1]
			startup = func() {
				out, err := runWithProgress(a.mw, "Menguji integritas…", "t", p)
				if err != nil {
					walk.MsgBox(a.mw, "Uji integritas", tailLines(out, 6), walk.MsgBoxOK|walk.MsgBoxIconError)
				} else {
					walk.MsgBox(a.mw, "Uji integritas", tailLines(out, 3), walk.MsgBoxOK|walk.MsgBoxIconInformation)
				}
				a.mw.Close()
			}
		}
	} else if len(args) == 1 && strings.HasSuffix(strings.ToLower(args[0]), ".zynx") {
		p := args[0]
		startup = func() { a.loadArchive(p) }
	}

	createErr := MainWindow{
		AssignTo: &a.mw,
		Title:    "zulip — pengarsip .zynx",
		MinSize:  Size{Width: 760, Height: 480},
		Size:     Size{Width: 900, Height: 560},
		Layout:   VBox{},
		MenuItems: []MenuItem{
			Menu{
				Text: "&Berkas",
				Items: []MenuItem{
					Action{Text: "&Buka arsip…", OnTriggered: func() { a.openArchiveDialog() }},
					Action{Text: "Buat arsip &baru…", OnTriggered: func() { a.showAdd(nil) }},
					Separator{},
					Action{Text: "Buat S&FX dari arsip ini (untuk dibagikan)…", OnTriggered: func() {
						if a.archive == "" {
							walk.MsgBox(a.mw, "Buat SFX", "Buka dulu arsip .zynx yang mau dibungkus.", walk.MsgBoxOK|walk.MsgBoxIconInformation)
							return
						}
						a.wrapSFXof(a.archive)
					}},
					Action{Text: "Ekspor sebagai &ZIP (universal)…", OnTriggered: func() {
						if a.archive == "" {
							walk.MsgBox(a.mw, "Ekspor ZIP", "Buka dulu arsip .zynx yang mau diekspor.", walk.MsgBoxOK|walk.MsgBoxIconInformation)
							return
						}
						a.toZipOf(a.archive)
					}},
					Separator{},
					Action{Text: "&Keluar", OnTriggered: func() { a.mw.Close() }},
				},
			},
			Menu{
				Text: "&Bantuan",
				Items: []MenuItem{
					Action{Text: "&Tentang zulip", OnTriggered: func() { a.showAbout() }},
				},
			},
		},
		OnDropFiles: func(files []string) {
			if len(files) == 1 && strings.HasSuffix(strings.ToLower(files[0]), ".zynx") {
				a.password = ""
				a.loadArchive(files[0])
				return
			}
			a.showAdd(files)
		},
		Children: []Widget{
			Composite{
				Background: SolidColorBrush{Color: walk.RGB(17, 17, 20)},
				Layout:     HBox{Margins: Margins{Left: 12, Top: 8, Right: 12, Bottom: 8}},
				Children: []Widget{
					ImageView{AssignTo: &a.logoView},
					Composite{
						Background: SolidColorBrush{Color: walk.RGB(17, 17, 20)},
						Layout:     VBox{MarginsZero: true, SpacingZero: true},
						Children: []Widget{
							Label{Text: "zulip", Font: Font{Family: "Segoe UI", PointSize: 15, Bold: true}, TextColor: walk.RGB(255, 255, 255)},
							Label{Text: "Pengarsip .zynx — terkecil saat disimpan, termudah saat dibagikan", Font: Font{Family: "Segoe UI", PointSize: 9}, TextColor: walk.RGB(190, 190, 195)},
						},
					},
					HSpacer{},
					Label{Text: "v" + guiVersion, Font: Font{Family: "Segoe UI", PointSize: 9}, TextColor: walk.RGB(245, 179, 1)},
				},
			},
			Composite{
				Layout: HBox{Margins: Margins{Left: 8, Top: 6, Right: 8, Bottom: 2}},
				Children: []Widget{
					PushButton{Text: "Buka…", OnClicked: func() { a.openArchiveDialog() }},
					PushButton{Text: "Buat arsip…", OnClicked: func() { a.showAdd(nil) }},
					PushButton{Text: "Ekstrak…", Font: Font{Bold: true}, OnClicked: func() { a.showExtract() }},
					PushButton{Text: "Uji integritas", OnClicked: func() {
						if a.archive == "" {
							walk.MsgBox(a.mw, "Uji", "Buka dulu arsipnya.", walk.MsgBoxOK|walk.MsgBoxIconInformation)
							return
						}
						args := []string{"t"}
						if a.password != "" {
							args = append(args, "-p"+a.password)
						}
						args = append(args, a.archive)
						a.runSimple("Uji integritas", args...)
					}},
					PushButton{Text: "Perbaiki", OnClicked: func() {
						if a.archive == "" {
							walk.MsgBox(a.mw, "Perbaiki", "Buka dulu arsipnya.", walk.MsgBoxOK|walk.MsgBoxIconInformation)
							return
						}
						a.runSimple("Perbaiki arsip", "repair", a.archive)
					}},
					HSpacer{},
				},
			},
			Label{AssignTo: &a.pathLabel, Text: "Belum ada arsip terbuka. Buka arsip .zynx, buat baru, atau jatuhkan berkas ke jendela ini."},
			TableView{
				AssignTo: &a.table,
				Model:    a.model,
				Columns: []TableViewColumn{
					{Title: "Nama", Width: 400},
					{Title: "Ukuran", Width: 110, Alignment: AlignFar},
					{Title: "Diubah", Width: 140},
					{Title: "Keterangan", Width: 150},
				},
			},
			Composite{
				Background: SolidColorBrush{Color: walk.RGB(238, 238, 240)},
				Layout:     HBox{Margins: Margins{Left: 10, Top: 4, Right: 10, Bottom: 4}},
				Children: []Widget{
					Label{AssignTo: &a.status, Text: "Siap."},
				},
			},
		},
	}.Create()
	if createErr != nil {
		// JANGAN abaikan error Create: satu properti kosmetik yang
		// gagal (LVM_SETCOLUMNWIDTH dari LastColumnStretched, terlihat
		// di Wine) pernah membuat jendela rusak dan Run() langsung
		// kembali — aplikasi tampak "tidak bisa dibuka" tanpa pesan.
		dbglog(fmt.Sprintf("create error: %v", createErr))
		if a.mw != nil {
			walk.MsgBox(a.mw, "zulip gagal memulai", createErr.Error(), walk.MsgBoxOK|walk.MsgBoxIconError)
		}
		return
	}

	setFormIcon(a.mw)
	if a.logoView != nil {
		if bmp := catBitmap(cat48PNG); bmp != nil {
			a.logoView.SetImage(bmp)
		}
	}
	dbglog("after icon")
	if startup != nil {
		go func() {
			time.Sleep(250 * time.Millisecond)
			a.mw.Synchronize(startup)
		}()
	}
	dbglog("before run")
	n := a.mw.Run()
	dbglog(fmt.Sprintf("run returned n=%d", n))
}
