package gp

import (
	"archive/zip"
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"testing"
)

// fakeCard answers just enough of a login to exercise the proof check, and records what it sent.
type fakeCard struct {
	key      []byte
	commands [][]byte
}

func (c *fakeCard) Transmit(command []byte) ([]byte, error) {
	c.commands = append(c.commands, append([]byte(nil), command...))
	switch {
	case command[1] == 0xA4:
		return []byte{0x90, 0x00}, nil
	case command[1] == 0x50:
		host := command[5:13]
		kdd := make([]byte, 10)
		sequence := []byte{0x00, 0x01}
		challenge := []byte{1, 2, 3, 4, 5, 6}
		enc, err := sessionKey(c.key, 0x82, sequence)
		if err != nil {
			return nil, err
		}
		proof, err := cryptogram(enc, concat(host, sequence, challenge))
		if err != nil {
			return nil, err
		}
		return concat(kdd, []byte{0x01, 0x02}, sequence, challenge, proof, []byte{0x90, 0x00}), nil
	case command[1] == 0x82:
		return []byte{0x90, 0x00}, nil
	}
	return []byte{0x6D, 0x00}, nil
}

func TestWrongKeysNeverSendTheLogin(t *testing.T) {
	card := &fakeCard{key: mustHex("00112233445566778899AABBCCDDEEFF")}
	if _, err := Open(card, DefaultKey); err != ErrWrongKeys {
		t.Fatalf("got %v, want ErrWrongKeys", err)
	}
	for _, command := range card.commands {
		if command[1] == 0x82 {
			t.Fatal("sent EXTERNAL AUTHENTICATE with keys the card didn't prove")
		}
	}
}

func TestMatchingKeysLogIn(t *testing.T) {
	card := &fakeCard{key: DefaultKey}
	session, err := Open(card, DefaultKey)
	if err != nil {
		t.Fatal(err)
	}
	if session.KeyVersion != 1 {
		t.Fatalf("key version %d", session.KeyVersion)
	}
	last := card.commands[len(card.commands)-1]
	if last[0] != 0x84 || last[1] != 0x82 || last[4] != 0x10 || len(last) != 21 {
		t.Fatalf("login command %X", last)
	}
}

// Single DES CBC with the last block triple encrypted, checked against a plain construction.
func TestRetailMAC(t *testing.T) {
	key := DefaultKey
	data := mustHex("84820100100011223344556677")
	got, err := retailMAC(key, data, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	padded := pad(data)
	single, _ := des.NewCipher(key[:8])
	prefix := make([]byte, len(padded)-8)
	cipher.NewCBCEncrypter(single, make([]byte, 8)).CryptBlocks(prefix, padded[:len(padded)-8])
	state := append([]byte(nil), padded[len(padded)-8:]...)
	for i := range state {
		state[i] ^= prefix[len(prefix)-8+i]
	}
	triple, _ := tripleBlock(key)
	triple.Encrypt(state, state)
	if !bytes.Equal(got, state) {
		t.Fatalf("got %s want %s", hex.EncodeToString(got), hex.EncodeToString(state))
	}
}

func TestLoadFileData(t *testing.T) {
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for _, part := range [][2]string{
		{"app/kachat/nfc/javacard/Applet.cap", "BB"},
		{"app/kachat/nfc/javacard/Header.cap", "AA"},
		{"app/kachat/nfc/javacard/Debug.cap", "ZZ"},
		{"META-INF/MANIFEST.MF", "ignored"},
	} {
		file, err := writer.Create(part[0])
		if err != nil {
			t.Fatal(err)
		}
		file.Write([]byte(part[1]))
	}
	writer.Close()

	got, err := LoadFileData(archive.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xC4, 4, 'A', 'A', 'B', 'B'}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %X want %X", got, want)
	}
}

func TestParseCardReplies(t *testing.T) {
	// The replies the project's own J3R180 gave.
	keys := mustHex("E012C00401018010C00402018010C00403018010")
	if got := parseKeyVersion(keys); got != 1 {
		t.Fatalf("key version %d", got)
	}
	resources := mustHex("FF211081020001820400027ED8830400000F98")
	if got := parseFreeMemory(resources); got != 163544 {
		t.Fatalf("free memory %d", got)
	}
}
