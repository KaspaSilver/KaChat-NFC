//go:build !windows

package pcsc

/*
#cgo darwin LDFLAGS: -framework PCSC
#cgo linux pkg-config: libpcsclite
#include <stdint.h>
#include <stdlib.h>
#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

// The types differ between macOS (32-bit) and pcsc-lite (long), so everything crosses into Go as
// fixed-width values.
static uint32_t shim_establish(uint64_t *ctx) {
	SCARDCONTEXT c = 0;
	LONG r = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &c);
	*ctx = (uint64_t)c;
	return (uint32_t)r;
}
static uint32_t shim_release(uint64_t ctx) {
	return (uint32_t)SCardReleaseContext((SCARDCONTEXT)ctx);
}
static uint32_t shim_list(uint64_t ctx, char *out, uint32_t *size) {
	DWORD n = *size;
	LONG r = SCardListReaders((SCARDCONTEXT)ctx, NULL, out, &n);
	*size = (uint32_t)n;
	return (uint32_t)r;
}
static uint32_t shim_connect(uint64_t ctx, const char *reader, uint64_t *card, uint32_t *proto) {
	SCARDHANDLE h = 0;
	DWORD p = 0;
	LONG r = SCardConnect((SCARDCONTEXT)ctx, reader, SCARD_SHARE_SHARED,
	                      SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &h, &p);
	*card = (uint64_t)h;
	*proto = (uint32_t)p;
	return (uint32_t)r;
}
static uint32_t shim_disconnect(uint64_t card, uint32_t disposition) {
	return (uint32_t)SCardDisconnect((SCARDHANDLE)card, (DWORD)disposition);
}
static uint32_t shim_atr(uint64_t card, uint8_t *atr, uint32_t *atrLen) {
	char name[256];
	DWORD nameLen = sizeof(name), state = 0, proto = 0, n = *atrLen;
	LONG r = SCardStatus((SCARDHANDLE)card, name, &nameLen, &state, &proto, atr, &n);
	*atrLen = (uint32_t)n;
	return (uint32_t)r;
}
static uint32_t shim_transmit(uint64_t card, uint32_t proto, const uint8_t *in, uint32_t inLen,
                              uint8_t *out, uint32_t *outLen) {
	DWORD n = *outLen;
	const SCARD_IO_REQUEST *pci = proto == SCARD_PROTOCOL_T1 ? SCARD_PCI_T1 : SCARD_PCI_T0;
	LONG r = SCardTransmit((SCARDHANDLE)card, pci, in, inLen, NULL, out, &n);
	*outLen = (uint32_t)n;
	return (uint32_t)r;
}
*/
import "C"

import (
	"strings"
	"unsafe"
)

// Context is a connection to the OS smart card service.
type Context struct{ handle C.uint64_t }

// Card is a connection to the card in one reader.
type Card struct {
	handle C.uint64_t
	proto  C.uint32_t
}

// Establish opens the smart card service.
func Establish() (*Context, error) {
	var handle C.uint64_t
	if err := statusError("SCardEstablishContext", uint32(C.shim_establish(&handle))); err != nil {
		return nil, err
	}
	return &Context{handle: handle}, nil
}

// Release closes the smart card service connection.
func (c *Context) Release() { C.shim_release(c.handle) }

// Readers lists the attached readers. No readers is an empty list, not an error.
func (c *Context) Readers() ([]string, error) {
	buffer := make([]byte, 8192)
	size := C.uint32_t(len(buffer))
	code := uint32(C.shim_list(c.handle, (*C.char)(unsafe.Pointer(&buffer[0])), &size))
	if code == scardENoReaders {
		return nil, nil
	}
	if err := statusError("SCardListReaders", code); err != nil {
		return nil, err
	}
	var readers []string
	for _, name := range strings.Split(string(buffer[:size]), "\x00") {
		if name != "" {
			readers = append(readers, name)
		}
	}
	return readers, nil
}

// Connect opens the card in a reader.
func (c *Context) Connect(reader string) (*Card, error) {
	name := C.CString(reader)
	defer C.free(unsafe.Pointer(name))
	card := &Card{}
	code := uint32(C.shim_connect(c.handle, name, &card.handle, &card.proto))
	if err := statusError("SCardConnect", code); err != nil {
		return nil, err
	}
	return card, nil
}

// ATR returns the card's answer to reset.
func (card *Card) ATR() ([]byte, error) {
	atr := make([]byte, 64)
	size := C.uint32_t(len(atr))
	code := uint32(C.shim_atr(card.handle, (*C.uint8_t)(&atr[0]), &size))
	if err := statusError("SCardStatus", code); err != nil {
		return nil, err
	}
	return atr[:size], nil
}

// Transmit sends one command and returns the response including its two status bytes.
func (card *Card) Transmit(command []byte) ([]byte, error) {
	response := make([]byte, maxResponse)
	size := C.uint32_t(len(response))
	code := uint32(C.shim_transmit(card.handle, card.proto, (*C.uint8_t)(&command[0]),
		C.uint32_t(len(command)), (*C.uint8_t)(&response[0]), &size))
	if err := statusError("SCardTransmit", code); err != nil {
		return nil, err
	}
	return response[:size], nil
}

// Close disconnects, leaving the card powered unless reset is true. Resetting drops any admin
// session and any verified PIN.
func (card *Card) Close(reset bool) {
	disposition := C.uint32_t(leaveCard)
	if reset {
		disposition = C.uint32_t(resetCard)
	}
	C.shim_disconnect(card.handle, disposition)
}
