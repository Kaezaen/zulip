package main

// Tiga penolong tampilan kecil yang di jalur baca asalnya tinggal di
// write.go; stub tidak menarik write.go (jalur kompres) demi ukuran.

import (
	"fmt"
	"strings"
)

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

func percentID(v float64) string {
	return strings.Replace(fmt.Sprintf("%.1f%%", v), ".", ",", 1)
}

func keyOrNone(k string) string {
	if k == "" {
		return "(none)"
	}
	return k
}
