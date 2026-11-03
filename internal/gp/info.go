package gp

import "fmt"

// CardInfo is what a card reports about itself without any login.
type CardInfo struct {
	// ICType comes from the card's production data (CPLC), for example D321.
	ICType string
	// KeyVersion is the admin key set's version, or -1 if the card doesn't say.
	KeyVersion int
	// FreeMemory is free persistent memory in bytes, or -1 if the card doesn't say.
	FreeMemory int
}

// ReadInfo reads public details from the card manager. It never starts a login, because some
// cards count an unfinished one against their failed login limit.
func ReadInfo(t Transmitter) (CardInfo, error) {
	info := CardInfo{KeyVersion: -1, FreeMemory: -1}
	selected, err := Send(t, []byte{0x00, 0xA4, 0x04, 0x00, 0x00})
	if err != nil {
		return info, err
	}
	if !selected.OK() {
		return info, fmt.Errorf("the card has no card manager (%04X)", selected.SW)
	}
	if cplc, err := Send(t, []byte{0x80, 0xCA, 0x9F, 0x7F, 0x00}); err == nil && cplc.OK() && len(cplc.Data) >= 7 {
		info.ICType = fmt.Sprintf("%02X%02X", cplc.Data[5], cplc.Data[6])
	}
	if keys, err := Send(t, []byte{0x80, 0xCA, 0x00, 0xE0, 0x00}); err == nil && keys.OK() {
		info.KeyVersion = parseKeyVersion(keys.Data)
	}
	if resources, err := Send(t, []byte{0x80, 0xCA, 0xFF, 0x21, 0x00}); err == nil && resources.OK() {
		info.FreeMemory = parseFreeMemory(resources.Data)
	}
	return info, nil
}

// E0 len { C0 len { key id, key version, type, length } ... }
func parseKeyVersion(data []byte) int {
	if len(data) < 6 || data[0] != 0xE0 || data[2] != 0xC0 {
		return -1
	}
	return int(data[5])
}

// FF21 len { 81 installed apps, 82 free persistent memory, 83 free transient memory }
func parseFreeMemory(data []byte) int {
	if len(data) < 3 || data[0] != 0xFF || data[1] != 0x21 {
		return -1
	}
	body := data[3:]
	for len(body) >= 2 {
		tag, length := body[0], int(body[1])
		if len(body) < 2+length {
			return -1
		}
		if tag == 0x82 {
			value := 0
			for _, b := range body[2 : 2+length] {
				value = value<<8 | int(b)
			}
			return value
		}
		body = body[2+length:]
	}
	return -1
}

// ChipName describes a known chip. Only the chips this project has tested are supported.
func ChipName(icType string) (name string, supported bool) {
	switch icType {
	case "D321":
		return "NXP JCOP 4 P71 (J3R180 family)", true
	case "":
		return "Unknown card", false
	}
	return "Untested card (chip " + icType + ")", false
}
