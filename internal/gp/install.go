package gp

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"path"
)

// The order the card expects the CAP file's components. Debug is never sent.
var capComponents = []string{
	"Header", "Directory", "Import", "Applet", "Class", "Method",
	"StaticField", "Export", "ConstantPool", "RefLocation", "Descriptor",
}

const maxLoadBlock = 247

// LoadFileData joins a CAP file's components into the block the card installs from.
func LoadFileData(capFile []byte) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(capFile), int64(len(capFile)))
	if err != nil {
		return nil, fmt.Errorf("not a CAP file: %w", err)
	}
	components := map[string][]byte{}
	for _, file := range reader.File {
		name := path.Base(file.Name)
		if path.Ext(name) != ".cap" {
			continue
		}
		stream, err := file.Open()
		if err != nil {
			return nil, err
		}
		content, err := io.ReadAll(stream)
		stream.Close()
		if err != nil {
			return nil, err
		}
		components[name[:len(name)-len(".cap")]] = content
	}
	if components["Header"] == nil || components["Applet"] == nil {
		return nil, errors.New("the CAP file has no applet in it")
	}
	var code []byte
	for _, name := range capComponents {
		code = append(code, components[name]...)
	}
	return concat([]byte{0xC4}, berLength(len(code)), code), nil
}

func berLength(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func lv(value []byte) []byte { return append([]byte{byte(len(value))}, value...) }

// Delete removes a package and its applet instances, erasing their data. A package that isn't
// there is fine.
func (s *Session) Delete(packageAID []byte) error {
	reply, err := s.Command(0xE4, 0x00, 0x80, concat([]byte{0x4F}, lv(packageAID)), true)
	if err != nil {
		return err
	}
	if !reply.OK() && reply.SW != 0x6A88 {
		return fmt.Errorf("the card refused to delete the old software (%04X)", reply.SW)
	}
	return nil
}

// Install loads a CAP file and makes one applet instance selectable.
func (s *Session) Install(capFile, packageAID, appletAID []byte) error {
	loadFile, err := LoadFileData(capFile)
	if err != nil {
		return err
	}
	prepare := concat(lv(packageAID), []byte{0x00, 0x00, 0x00, 0x00})
	reply, err := s.Command(0xE6, 0x02, 0x00, prepare, true)
	if err != nil {
		return err
	}
	if !reply.OK() {
		return fmt.Errorf("the card refused to start the install (%04X)", reply.SW)
	}

	sequence := 0
	for offset := 0; offset < len(loadFile); offset += maxLoadBlock {
		end := offset + maxLoadBlock
		p1 := byte(0x00)
		if end >= len(loadFile) {
			end = len(loadFile)
			p1 = 0x80
		}
		if sequence > 0xFF {
			return errors.New("the applet is too big to load")
		}
		reply, err = s.Command(0xE8, p1, byte(sequence), loadFile[offset:end], true)
		if err != nil {
			return err
		}
		if !reply.OK() {
			return fmt.Errorf("the card refused block %d of the install (%04X)", sequence, reply.SW)
		}
		sequence++
	}

	// Package, applet class, instance, no privileges, empty install parameters, no token.
	install := concat(lv(packageAID), lv(appletAID), lv(appletAID),
		[]byte{0x01, 0x00}, []byte{0x02, 0xC9, 0x00}, []byte{0x00})
	reply, err = s.Command(0xE6, 0x0C, 0x00, install, true)
	if err != nil {
		return err
	}
	if !reply.OK() {
		return fmt.Errorf("the card refused to activate the software (%04X)", reply.SW)
	}
	return nil
}

// NewAdminKey makes a random key on this computer. The card only ever receives it.
func NewAdminKey() ([]byte, error) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// ReplaceKeys sets one new key as all three admin keys and returns the card's new key version.
// A version of 2 or above marks the card as no longer on factory keys.
func (s *Session) ReplaceKeys(newKey []byte) (byte, error) {
	if len(newKey) != 16 {
		return 0, errors.New("an admin key is 16 bytes")
	}
	current := s.KeyVersion
	var p1, next byte
	switch {
	case current == 0xFF:
		// Factory keys aren't replaced by version: a new set takes over from them.
		p1, next = 0x00, 0x02
	case current >= 0x7F:
		return 0, fmt.Errorf("the card is on key version %d, which this tool can't move on from", current)
	default:
		p1, next = current, current+1
	}

	wrapped, err := tripleECB(s.sessionDEK, newKey)
	if err != nil {
		return 0, err
	}
	check, err := tripleECB(newKey, make([]byte, 8))
	if err != nil {
		return 0, err
	}
	entry := concat([]byte{0x80, 0x10}, wrapped, []byte{0x03}, check[:3])
	data := concat([]byte{next}, entry, entry, entry)

	reply, err := s.Command(0xD8, p1, 0x81, data, true)
	if err != nil {
		return 0, err
	}
	if !reply.OK() {
		return 0, fmt.Errorf("the card refused the new admin keys (%04X)", reply.SW)
	}
	want := concat([]byte{next}, check[:3], check[:3], check[:3])
	if !bytes.Equal(reply.Data, want) {
		return 0, fmt.Errorf("the card confirmed different keys than the ones sent (%X)", reply.Data)
	}
	return next, nil
}
