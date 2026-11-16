//go:build windows

package main

// Konsol Windows lama (conhost) tidak memproses kode warna ANSI secara
// bawaan. Aktifkan ENABLE_VIRTUAL_TERMINAL_PROCESSING pada stdout dan
// stderr agar tampilan v0.6 (warna, progress bar) tampil benar di
// Command Prompt / PowerShell / Windows Terminal.

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32           = syscall.NewLazyDLL("kernel32.dll")
	procGetConsoleMode = kernel32.NewProc("GetConsoleMode")
	procSetConsoleMode = kernel32.NewProc("SetConsoleMode")
)

const enableVirtualTerminalProcessing = 0x0004

func enableVT(f *os.File) {
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(f.Fd(), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return // bukan konsol (mis. di-pipe): tidak ada yang perlu diubah
	}
	procSetConsoleMode.Call(f.Fd(), uintptr(mode|enableVirtualTerminalProcessing))
}

func init() {
	enableVT(os.Stdout)
	enableVT(os.Stderr)
}
