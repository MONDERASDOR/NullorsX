package internal

import (
	"net/http"
	"os"
	"github.com/fatih/color"
)

func DetectFileType(filename string) string {
	file, err := os.Open(filename)
	if err != nil {
		return color.HiRedString("File error: %v", err)
	}
	defer file.Close()
	buf := make([]byte, 512)
	file.Read(buf)
	return http.DetectContentType(buf)
}
