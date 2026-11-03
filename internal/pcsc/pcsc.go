// Package pcsc is a small binding to the smart card service every desktop OS ships: PCSC.framework
// on macOS, winscard.dll on Windows and pcsc-lite on Linux. It's hand written so this tool, which
// writes to a card that holds a backup, has no third-party dependencies.
package pcsc

import (
	"errors"
	"fmt"
)

// ErrNoCard means the reader is there but has no card in it.
var ErrNoCard = errors.New("no card in the reader")

// ErrNoService means the OS smart card service isn't running or no reader has ever been attached.
var ErrNoService = errors.New("smart card service unavailable")

// Windows and PC/SC Lite share these status codes.
const (
	scardSuccess         = 0x00000000
	scardENoSmartcard    = 0x8010000C
	scardENoService      = 0x8010001D
	scardENoReaders      = 0x8010002E
	scardEServiceStopped = 0x8010001E
	scardEReaderUnavail  = 0x80100017
	scardWRemovedCard    = 0x80100069
	scardWUnpoweredCard  = 0x80100067
	scardWUnresponsive   = 0x80100066
	scardWResetCard      = 0x80100068
	shareShared          = 2
	protocolT0           = 1
	protocolT1           = 2
	leaveCard            = 0
	resetCard            = 1
	maxResponse          = 65538
)

func statusError(call string, code uint32) error {
	switch code {
	case scardSuccess:
		return nil
	case scardENoSmartcard, scardWRemovedCard:
		return ErrNoCard
	case scardENoService, scardEServiceStopped:
		return ErrNoService
	}
	return fmt.Errorf("%s failed: 0x%08X", call, code)
}
