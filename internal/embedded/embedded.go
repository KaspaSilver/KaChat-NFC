// Package embedded holds the applet this build of the helper writes to cards. CI places the CAP
// file here before building, so a helper can only ever load the one applet it was released with,
// and nothing that talks to it can supply another.
package embedded

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
)

//go:embed all:files
var files embed.FS

// Applet returns the embedded CAP file.
func Applet() ([]byte, error) {
	content, err := files.ReadFile("files/KaChatNFC.cap")
	if err != nil {
		return nil, errors.New("this build has no applet in it")
	}
	return content, nil
}

// AppletSHA256 is the embedded CAP file's hash, or empty if there isn't one.
func AppletSHA256() string {
	content, err := Applet()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
