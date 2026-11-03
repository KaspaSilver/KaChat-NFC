//go:build windows

package pcsc

import (
	"syscall"
	"unsafe"
)

var (
	winscard       = syscall.NewLazyDLL("winscard.dll")
	procEstablish  = winscard.NewProc("SCardEstablishContext")
	procRelease    = winscard.NewProc("SCardReleaseContext")
	procList       = winscard.NewProc("SCardListReadersW")
	procConnect    = winscard.NewProc("SCardConnectW")
	procDisconnect = winscard.NewProc("SCardDisconnect")
	procStatus     = winscard.NewProc("SCardStatusW")
	procTransmit   = winscard.NewProc("SCardTransmit")
	pciT0          = winscard.NewProc("g_rgSCardT0Pci")
	pciT1          = winscard.NewProc("g_rgSCardT1Pci")
)

// Context is a connection to the OS smart card service.
type Context struct{ handle uintptr }

// Card is a connection to the card in one reader.
type Card struct {
	handle uintptr
	proto  uint32
}

// Establish opens the smart card service.
func Establish() (*Context, error) {
	var handle uintptr
	code, _, _ := procEstablish.Call(2, 0, 0, uintptr(unsafe.Pointer(&handle)))
	if err := statusError("SCardEstablishContext", uint32(code)); err != nil {
		return nil, err
	}
	return &Context{handle: handle}, nil
}

// Release closes the smart card service connection.
func (c *Context) Release() { procRelease.Call(c.handle) }

// Readers lists the attached readers. No readers is an empty list, not an error.
func (c *Context) Readers() ([]string, error) {
	buffer := make([]uint16, 8192)
	size := uint32(len(buffer))
	code, _, _ := procList.Call(c.handle, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if uint32(code) == scardENoReaders {
		return nil, nil
	}
	if err := statusError("SCardListReaders", uint32(code)); err != nil {
		return nil, err
	}
	var readers []string
	start := 0
	for i := 0; i < int(size); i++ {
		if buffer[i] == 0 {
			if i > start {
				readers = append(readers, syscall.UTF16ToString(buffer[start:i]))
			}
			start = i + 1
		}
	}
	return readers, nil
}

// Connect opens the card in a reader.
func (c *Context) Connect(reader string) (*Card, error) {
	name, err := syscall.UTF16PtrFromString(reader)
	if err != nil {
		return nil, err
	}
	card := &Card{}
	code, _, _ := procConnect.Call(c.handle, uintptr(unsafe.Pointer(name)), shareShared, protocolT0|protocolT1,
		uintptr(unsafe.Pointer(&card.handle)), uintptr(unsafe.Pointer(&card.proto)))
	if err := statusError("SCardConnect", uint32(code)); err != nil {
		return nil, err
	}
	return card, nil
}

// ATR returns the card's answer to reset.
func (card *Card) ATR() ([]byte, error) {
	atr := make([]byte, 64)
	nameLength := uint32(0)
	var state, proto uint32
	size := uint32(len(atr))
	code, _, _ := procStatus.Call(card.handle, 0, uintptr(unsafe.Pointer(&nameLength)),
		uintptr(unsafe.Pointer(&state)), uintptr(unsafe.Pointer(&proto)),
		uintptr(unsafe.Pointer(&atr[0])), uintptr(unsafe.Pointer(&size)))
	if err := statusError("SCardStatus", uint32(code)); err != nil {
		return nil, err
	}
	return atr[:size], nil
}

// Transmit sends one command and returns the response including its two status bytes.
func (card *Card) Transmit(command []byte) ([]byte, error) {
	pci := pciT0
	if card.proto == protocolT1 {
		pci = pciT1
	}
	response := make([]byte, maxResponse)
	size := uint32(len(response))
	code, _, _ := procTransmit.Call(card.handle, pci.Addr(), uintptr(unsafe.Pointer(&command[0])),
		uintptr(len(command)), 0, uintptr(unsafe.Pointer(&response[0])), uintptr(unsafe.Pointer(&size)))
	if err := statusError("SCardTransmit", uint32(code)); err != nil {
		return nil, err
	}
	return response[:size], nil
}

// Close disconnects, leaving the card powered unless reset is true. Resetting drops any admin
// session and any verified PIN.
func (card *Card) Close(reset bool) {
	disposition := uintptr(leaveCard)
	if reset {
		disposition = resetCard
	}
	procDisconnect.Call(card.handle, disposition)
}
