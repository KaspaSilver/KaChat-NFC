// Package gp speaks just enough GlobalPlatform to install an applet and change a card's admin
// keys: an SCP02 admin session with C-MAC, and the install, delete and put-key commands.
package gp

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// DefaultKey is GlobalPlatform's public test key, which blank cards ship with.
var DefaultKey = mustHex("404142434445464748494A4B4C4D4E4F")

var (
	// ErrWrongKeys means the card did not prove it holds the key. No login was sent.
	ErrWrongKeys = errors.New("the card's admin keys don't match")
	// ErrUnsupportedChannel means the card doesn't offer SCP02.
	ErrUnsupportedChannel = errors.New("the card uses a secure channel this tool doesn't support")
	// ErrLoginRefused means the card rejected a login it had already proved keys for.
	ErrLoginRefused = errors.New("the card refused the admin login")
)

// Transmitter is a connected card.
type Transmitter interface {
	Transmit(command []byte) ([]byte, error)
}

// Response is a card's reply split into data and status word.
type Response struct {
	Data []byte
	SW   uint16
}

// OK reports the success status word.
func (r Response) OK() bool { return r.SW == 0x9000 }

// Send sends one command, following the two status words that ask for a resend.
func Send(t Transmitter, command []byte) (Response, error) {
	raw, err := t.Transmit(command)
	if err != nil {
		return Response{}, err
	}
	var data []byte
	for {
		if len(raw) < 2 {
			return Response{}, fmt.Errorf("card sent a %d-byte response", len(raw))
		}
		sw1, sw2 := raw[len(raw)-2], raw[len(raw)-1]
		data = append(data, raw[:len(raw)-2]...)
		switch sw1 {
		case 0x61:
			raw, err = t.Transmit([]byte{0x00, 0xC0, 0x00, 0x00, sw2})
		case 0x6C:
			retry := append([]byte(nil), command...)
			retry[len(retry)-1] = sw2
			raw, err = t.Transmit(retry)
		default:
			return Response{Data: data, SW: uint16(sw1)<<8 | uint16(sw2)}, nil
		}
		if err != nil {
			return Response{}, err
		}
	}
}

// Session is a logged-in admin session on the card manager.
type Session struct {
	t             Transmitter
	sessionMAC    []byte
	sessionDEK    []byte
	lastMAC       []byte
	KeyVersion    byte
	SecurityLevel byte
}

// Open logs in with key, which is used for all three admin keys. The card proves it holds the key
// first, and the login is only sent if it does, so wrong keys never reach the step that a card
// counts as a failed login.
func Open(t Transmitter, key []byte) (*Session, error) {
	if len(key) != 16 {
		return nil, errors.New("an admin key is 16 bytes")
	}
	selected, err := Send(t, []byte{0x00, 0xA4, 0x04, 0x00, 0x00})
	if err != nil {
		return nil, err
	}
	if !selected.OK() {
		return nil, fmt.Errorf("the card has no card manager to select (%04X)", selected.SW)
	}

	host := make([]byte, 8)
	if _, err := rand.Read(host); err != nil {
		return nil, err
	}
	init, err := Send(t, append(append([]byte{0x80, 0x50, 0x00, 0x00, 0x08}, host...), 0x00))
	if err != nil {
		return nil, err
	}
	if !init.OK() {
		return nil, fmt.Errorf("the card refused to start a login (%04X)", init.SW)
	}
	if len(init.Data) != 28 {
		return nil, ErrUnsupportedChannel
	}
	keyVersion, channel := init.Data[10], init.Data[11]
	if channel != 2 {
		return nil, ErrUnsupportedChannel
	}
	sequence := init.Data[12:14]
	cardChallenge := init.Data[14:20]
	cardCryptogram := init.Data[20:28]

	sessionENC, err := sessionKey(key, 0x82, sequence)
	if err != nil {
		return nil, err
	}
	expected, err := cryptogram(sessionENC, concat(host, sequence, cardChallenge))
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(expected, cardCryptogram) {
		return nil, ErrWrongKeys
	}

	sessionMAC, err := sessionKey(key, 0x01, sequence)
	if err != nil {
		return nil, err
	}
	sessionDEK, err := sessionKey(key, 0x81, sequence)
	if err != nil {
		return nil, err
	}
	hostCryptogram, err := cryptogram(sessionENC, concat(sequence, cardChallenge, host))
	if err != nil {
		return nil, err
	}

	header := []byte{0x84, 0x82, 0x01, 0x00, 0x10}
	mac, err := retailMAC(sessionMAC, concat(header, hostCryptogram), make([]byte, 8))
	if err != nil {
		return nil, err
	}
	reply, err := Send(t, concat(header, hostCryptogram, mac))
	if err != nil {
		return nil, err
	}
	if !reply.OK() {
		return nil, fmt.Errorf("%w (%04X)", ErrLoginRefused, reply.SW)
	}
	return &Session{t: t, sessionMAC: sessionMAC, sessionDEK: sessionDEK, lastMAC: mac, KeyVersion: keyVersion, SecurityLevel: 1}, nil
}

// Command sends a command in the session. Each C-MAC chains from the last one, encrypted first.
func (s *Session) Command(ins, p1, p2 byte, data []byte, expectResponse bool) (Response, error) {
	if len(data) > 247 {
		return Response{}, errors.New("command data too long")
	}
	header := []byte{0x84, ins, p1, p2, byte(len(data) + 8)}
	block, err := des.NewCipher(s.sessionMAC[:8])
	if err != nil {
		return Response{}, err
	}
	icv := make([]byte, 8)
	block.Encrypt(icv, s.lastMAC)
	mac, err := retailMAC(s.sessionMAC, concat(header, data), icv)
	if err != nil {
		return Response{}, err
	}
	s.lastMAC = mac
	command := concat(header, data, mac)
	if expectResponse {
		command = append(command, 0x00)
	}
	return Send(s.t, command)
}

func sessionKey(key []byte, constant byte, sequence []byte) ([]byte, error) {
	input := make([]byte, 16)
	input[0], input[1] = 0x01, constant
	copy(input[2:], sequence)
	return tripleCBC(key, input)
}

func tripleBlock(key []byte) (cipher.Block, error) {
	return des.NewTripleDESCipher(concat(key, key[:8]))
}

func tripleCBC(key, data []byte) ([]byte, error) {
	block, err := tripleBlock(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, make([]byte, 8)).CryptBlocks(out, data)
	return out, nil
}

func tripleECB(key, data []byte) ([]byte, error) {
	block, err := tripleBlock(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 8 {
		block.Encrypt(out[i:i+8], data[i:i+8])
	}
	return out, nil
}

func pad(data []byte) []byte {
	out := append(append([]byte(nil), data...), 0x80)
	for len(out)%8 != 0 {
		out = append(out, 0)
	}
	return out
}

func cryptogram(sessionENC, data []byte) ([]byte, error) {
	out, err := tripleCBC(sessionENC, pad(data))
	if err != nil {
		return nil, err
	}
	return out[len(out)-8:], nil
}

// retailMAC is single DES CBC over all but the last block, then triple DES on the last.
func retailMAC(key, data, icv []byte) ([]byte, error) {
	padded := pad(data)
	single, err := des.NewCipher(key[:8])
	if err != nil {
		return nil, err
	}
	triple, err := tripleBlock(key)
	if err != nil {
		return nil, err
	}
	state := append([]byte(nil), icv...)
	for i := 0; i < len(padded); i += 8 {
		for j := 0; j < 8; j++ {
			state[j] ^= padded[i+j]
		}
		if i+8 < len(padded) {
			single.Encrypt(state, state)
		} else {
			triple.Encrypt(state, state)
		}
	}
	return state, nil
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

func mustHex(s string) []byte {
	out, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return out
}
