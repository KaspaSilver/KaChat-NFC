package gp

import (
	"crypto/sha256"
	"errors"
	"fmt"
)

// The IDs in applet/build.xml. F0 marks them as proprietary, followed by "KACHAT" and "NFC".
var (
	PackageAID = mustHex("F04B41434841544E4643")
	AppletAID  = mustHex("F04B41434841544E464301")
)

// AppletStatus is the applet's answer to SELECT or STATUS. See docs/PROTOCOL.md.
type AppletStatus struct {
	Protocol       int  `json:"protocol"`
	Major          int  `json:"major"`
	Minor          int  `json:"minor"`
	PINSet         bool `json:"pinSet"`
	HasBackup      bool `json:"hasBackup"`
	PINBlocked     bool `json:"pinBlocked"`
	TriesRemaining int  `json:"triesRemaining"`
	MaxBackup      int  `json:"maxBackup"`
}

// Version is the applet's version as text.
func (s AppletStatus) Version() string { return fmt.Sprintf("%d.%d", s.Major, s.Minor) }

// SelectApplet selects the KaChat-NFC applet, returning false if the card doesn't have it.
func SelectApplet(t Transmitter) (*AppletStatus, bool, error) {
	reply, err := Send(t, concat([]byte{0x00, 0xA4, 0x04, 0x00}, lv(AppletAID), []byte{0x00}))
	if err != nil {
		return nil, false, err
	}
	if reply.SW == 0x6A82 || reply.SW == 0x6999 {
		return nil, false, nil
	}
	if !reply.OK() {
		return nil, false, fmt.Errorf("selecting the applet failed (%04X)", reply.SW)
	}
	if len(reply.Data) != 7 {
		return nil, false, fmt.Errorf("the applet sent a %d-byte status", len(reply.Data))
	}
	flags := reply.Data[3]
	return &AppletStatus{
		Protocol:       int(reply.Data[0]),
		Major:          int(reply.Data[1]),
		Minor:          int(reply.Data[2]),
		PINSet:         flags&0x01 != 0,
		HasBackup:      flags&0x02 != 0,
		PINBlocked:     flags&0x04 != 0,
		TriesRemaining: int(reply.Data[4]),
		MaxBackup:      int(reply.Data[5])<<8 | int(reply.Data[6]),
	}, true, nil
}

func appletCommand(t Transmitter, ins byte, p1p2 int, data []byte, le bool) (Response, error) {
	command := []byte{0x80, ins, byte(p1p2 >> 8), byte(p1p2)}
	if len(data) > 0 {
		command = append(append(command, byte(len(data))), data...)
	}
	if le {
		command = append(command, 0x00)
	}
	return Send(t, command)
}

// SetPIN sets the first PIN.
func SetPIN(t Transmitter, pin string) error {
	reply, err := appletCommand(t, 0x21, 0, []byte(pin), false)
	if err != nil {
		return err
	}
	if !reply.OK() {
		return fmt.Errorf("set PIN failed (%04X)", reply.SW)
	}
	return nil
}

// VerifyPIN checks the PIN.
func VerifyPIN(t Transmitter, pin string) error {
	reply, err := appletCommand(t, 0x20, 0, []byte(pin), false)
	if err != nil {
		return err
	}
	if !reply.OK() {
		return fmt.Errorf("verify PIN failed (%04X)", reply.SW)
	}
	return nil
}

// WriteBackup saves a backup in chunks and commits it with its hash.
func WriteBackup(t Transmitter, backup []byte) error {
	reply, err := appletCommand(t, 0xD0, len(backup), nil, false)
	if err != nil {
		return err
	}
	if !reply.OK() {
		return fmt.Errorf("write begin failed (%04X)", reply.SW)
	}
	const chunk = 200
	for offset := 0; offset < len(backup); offset += chunk {
		end := min(offset+chunk, len(backup))
		reply, err = appletCommand(t, 0xD1, offset, backup[offset:end], false)
		if err != nil {
			return err
		}
		if !reply.OK() {
			return fmt.Errorf("write at %d failed (%04X)", offset, reply.SW)
		}
	}
	hash := sha256.Sum256(backup)
	reply, err = appletCommand(t, 0xD2, 0, hash[:], false)
	if err != nil {
		return err
	}
	if !reply.OK() {
		return fmt.Errorf("commit failed (%04X)", reply.SW)
	}
	return nil
}

// ReadBackup reads the whole backup.
func ReadBackup(t Transmitter) ([]byte, error) {
	var backup []byte
	for {
		reply, err := appletCommand(t, 0xB0, len(backup), nil, true)
		if err != nil {
			return nil, err
		}
		if !reply.OK() {
			return nil, fmt.Errorf("read failed (%04X)", reply.SW)
		}
		if len(reply.Data) == 0 {
			return backup, nil
		}
		backup = append(backup, reply.Data...)
	}
}

// Wipe erases the backup.
func Wipe(t Transmitter) error {
	reply, err := appletCommand(t, 0xE0, 0, nil, false)
	if err != nil {
		return err
	}
	if !reply.OK() {
		return errors.New("wipe failed")
	}
	return nil
}
