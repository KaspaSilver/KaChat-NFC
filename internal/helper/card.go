// Package helper finds readers and cards and does the two jobs that write to a card: loading the
// applet and replacing the admin keys. The CLI and the local HTTP service both use it.
package helper

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/KaspaSilver/KaChat-NFC/internal/embedded"
	"github.com/KaspaSilver/KaChat-NFC/internal/gp"
	"github.com/KaspaSilver/KaChat-NFC/internal/pcsc"
)

// Error is a failure with a stable code the panel can show its own wording for.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	// AdminKey is only set if keys changed and the follow-up check failed, so it's never lost.
	AdminKey string `json:"adminKey,omitempty"`
}

func (e *Error) Error() string { return e.Message }

func fail(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// CardState says what a card is ready for.
type CardState string

const (
	// StateBlank has no KaChat-NFC applet yet.
	StateBlank CardState = "blank"
	// StateLoaded already has the applet.
	StateLoaded CardState = "loaded"
	// StateUnreadable didn't answer like a Java Card.
	StateUnreadable CardState = "unreadable"
)

// CardReport is one card's public details.
type CardReport struct {
	ATR              string           `json:"atr"`
	Chip             string           `json:"chip"`
	Supported        bool             `json:"supported"`
	State            CardState        `json:"state"`
	Applet           *gp.AppletStatus `json:"applet,omitempty"`
	AppletVersion    string           `json:"appletVersion,omitempty"`
	AdminKeyVersion  int              `json:"adminKeyVersion"`
	AdminKeysChanged bool             `json:"adminKeysChanged"`
	FreeMemoryBytes  int              `json:"freeMemoryBytes"`
}

// ReaderReport is one reader and the card in it, if any.
type ReaderReport struct {
	Name string      `json:"name"`
	Card *CardReport `json:"card"`
}

// Status is the whole picture the panel polls for.
type Status struct {
	HelperVersion string         `json:"helperVersion"`
	AppletVersion string         `json:"appletVersion"`
	AppletSHA256  string         `json:"appletSha256"`
	Readers       []ReaderReport `json:"readers"`
}

// AppletVersion is the version of the applet this project currently embeds.
const AppletVersion = "1.1"

// maxLoginFailures limits proof failures per card each time the helper runs. A mismatch never
// sends a login, but some cards still count an unfinished one, so this stops anything hammering it.
const maxLoginFailures = 3

// Service does the card work. Calls are one at a time, since a card can't do two things at once.
type Service struct {
	Version string

	mu       sync.Mutex
	failures map[string]int
	cache    map[string]*CardReport
}

// NewService makes a Service.
func NewService(version string) *Service {
	return &Service{Version: version, failures: map[string]int{}, cache: map[string]*CardReport{}}
}

// Status lists readers and what's in them. A card is only inspected once after it's inserted.
func (s *Service) Status() (*Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := &Status{
		HelperVersion: s.Version,
		AppletVersion: AppletVersion,
		AppletSHA256:  embedded.AppletSHA256(),
		Readers:       []ReaderReport{},
	}
	context, err := pcsc.Establish()
	if err != nil {
		// Windows reports no service until a reader has been attached once.
		if errors.Is(err, pcsc.ErrNoService) {
			return status, nil
		}
		return nil, err
	}
	defer context.Release()
	readers, err := context.Readers()
	if err != nil {
		if errors.Is(err, pcsc.ErrNoService) {
			return status, nil
		}
		return nil, err
	}
	for _, name := range readers {
		report := ReaderReport{Name: name}
		card, err := context.Connect(name)
		if err == nil {
			report.Card = s.inspect(name, card)
			card.Close(false)
		} else if errors.Is(err, pcsc.ErrNoCard) {
			delete(s.cache, name)
		} else {
			delete(s.cache, name)
			report.Card = &CardReport{Chip: "Unreadable card", State: StateUnreadable, AdminKeyVersion: -1, FreeMemoryBytes: -1}
		}
		status.Readers = append(status.Readers, report)
	}
	return status, nil
}

func (s *Service) inspect(reader string, card *pcsc.Card) *CardReport {
	atrBytes, _ := card.ATR()
	atr := strings.ToUpper(hex.EncodeToString(atrBytes))
	if cached := s.cache[reader]; cached != nil && cached.ATR == atr {
		return cached
	}
	report := readCard(card, atr)
	s.cache[reader] = report
	return report
}

func readCard(card *pcsc.Card, atr string) *CardReport {
	report := &CardReport{ATR: atr, State: StateUnreadable, AdminKeyVersion: -1, FreeMemoryBytes: -1, Chip: "Unreadable card"}
	info, err := gp.ReadInfo(card)
	if err != nil {
		return report
	}
	report.Chip, report.Supported = gp.ChipName(info.ICType)
	report.AdminKeyVersion = info.KeyVersion
	report.AdminKeysChanged = info.KeyVersion >= 2 && info.KeyVersion != 0xFF
	report.FreeMemoryBytes = info.FreeMemory
	applet, present, err := gp.SelectApplet(card)
	if err != nil {
		return report
	}
	report.State = StateBlank
	if present {
		report.State = StateLoaded
		report.Applet = applet
		report.AppletVersion = applet.Version()
	}
	return report
}

// connect finds the one card to act on. With several cards in, the caller has to name a reader.
func connect(context *pcsc.Context, reader string) (*pcsc.Card, string, error) {
	if reader != "" {
		card, err := context.Connect(reader)
		if errors.Is(err, pcsc.ErrNoCard) {
			return nil, "", fail("no_card", "There's no card in %s.", reader)
		}
		return card, reader, err
	}
	readers, err := context.Readers()
	if err != nil {
		return nil, "", err
	}
	var found *pcsc.Card
	var foundName string
	for _, name := range readers {
		card, err := context.Connect(name)
		if err != nil {
			continue
		}
		if found != nil {
			card.Close(false)
			found.Close(false)
			return nil, "", fail("multiple_cards", "There's more than one card in. Remove the others, or choose a reader.")
		}
		found, foundName = card, name
	}
	if found == nil {
		if len(readers) == 0 {
			return nil, "", fail("no_reader", "No card reader was found.")
		}
		return nil, "", fail("no_card", "There's no card in the reader.")
	}
	return found, foundName, nil
}

func parseAdminKey(value string) ([]byte, error) {
	if value == "" {
		return gp.DefaultKey, nil
	}
	key, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
	if err != nil || len(key) != 16 {
		return nil, fail("bad_admin_key", "An admin key is 32 hex characters.")
	}
	return key, nil
}

// login opens an admin session, stopping for good once a card has failed too often.
func (s *Service) login(card *pcsc.Card, reader string, key []byte) (*gp.Session, error) {
	atr, _ := card.ATR()
	id := reader + "/" + hex.EncodeToString(atr)
	if s.failures[id] >= maxLoginFailures {
		return nil, fail("too_many_attempts", "Stopped trying admin keys on this card to protect it. Check the key, then restart the helper.")
	}
	session, err := gp.Open(card, key)
	switch {
	case err == nil:
		delete(s.failures, id)
		return session, nil
	case errors.Is(err, gp.ErrWrongKeys):
		s.failures[id]++
		return nil, fail("wrong_admin_key", "This card's admin keys are different. Nothing was changed. If you saved its admin key, enter it.")
	case errors.Is(err, gp.ErrUnsupportedChannel):
		return nil, fail("unsupported_card", "This card uses a login method this tool doesn't support. Nothing was changed.")
	case errors.Is(err, gp.ErrLoginRefused):
		s.failures[id]++
		return nil, fail("login_refused", "The card refused the admin login. Nothing was changed.")
	}
	return nil, cardError(err)
}

func cardError(err error) error {
	if errors.Is(err, pcsc.ErrNoCard) {
		return fail("card_removed", "The card was removed. Put it back and try again.")
	}
	return err
}

// LoadRequest asks for the applet to be written to a card.
type LoadRequest struct {
	Reader string `json:"reader"`
	// ConfirmErase has to be true to reload a card that already has the applet, since that erases
	// its backup and PIN.
	ConfirmErase bool   `json:"confirmErase"`
	AdminKey     string `json:"adminKey"`
}

// LoadResult reports a finished load.
type LoadResult struct {
	Reader        string `json:"reader"`
	AppletVersion string `json:"appletVersion"`
	AppletSHA256  string `json:"appletSha256"`
	Replaced      bool   `json:"replaced"`
}

// Load writes the embedded applet to the card and confirms it answers.
func (s *Service) Load(request LoadRequest) (*LoadResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	capFile, err := embedded.Applet()
	if err != nil {
		return nil, fail("no_applet_in_build", "%s", err.Error())
	}
	key, err := parseAdminKey(request.AdminKey)
	if err != nil {
		return nil, err
	}
	context, err := pcsc.Establish()
	if err != nil {
		return nil, fail("no_reader", "No card reader was found.")
	}
	defer context.Release()
	card, reader, err := connect(context, request.Reader)
	if err != nil {
		return nil, err
	}
	defer card.Close(true)
	delete(s.cache, reader)

	info, err := gp.ReadInfo(card)
	if err != nil {
		return nil, fail("unsupported_card", "This doesn't look like a Java Card. Nothing was changed.")
	}
	if _, supported := gp.ChipName(info.ICType); !supported {
		return nil, fail("unsupported_card", "KaChat-NFC has only been tested on J3R180 cards, so this one wasn't changed.")
	}
	existing, present, err := gp.SelectApplet(card)
	if err != nil {
		return nil, cardError(err)
	}
	if present && !request.ConfirmErase {
		problem := fail("would_erase", "This card already has KaChat-NFC. Loading it again erases its PIN and any backup on it.")
		if !existing.HasBackup {
			problem.Message = "This card already has KaChat-NFC. Loading it again erases its PIN."
		}
		return nil, problem
	}

	session, err := s.login(card, reader, key)
	if err != nil {
		return nil, err
	}
	if err := session.Delete(gp.PackageAID); err != nil {
		return nil, cardError(err)
	}
	if err := session.Install(capFile, gp.PackageAID, gp.AppletAID); err != nil {
		return nil, cardError(err)
	}

	loaded, ok, err := gp.SelectApplet(card)
	if err != nil {
		return nil, cardError(err)
	}
	if !ok {
		return nil, fail("verify_failed", "The install finished, but the card doesn't answer as KaChat-NFC.")
	}
	return &LoadResult{Reader: reader, AppletVersion: loaded.Version(), AppletSHA256: embedded.AppletSHA256(), Replaced: present}, nil
}

// SecureRequest asks for a card's admin keys to be replaced.
type SecureRequest struct {
	Reader   string `json:"reader"`
	AdminKey string `json:"adminKey"`
}

// SecureResult carries the new key. It's never written to disk, so this is the only copy.
type SecureResult struct {
	Reader          string `json:"reader"`
	AdminKey        string `json:"adminKey"`
	AdminKeyVersion int    `json:"adminKeyVersion"`
}

// Secure replaces the admin keys with a new random key and proves the card accepts it.
func (s *Service) Secure(request SecureRequest) (*SecureResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := parseAdminKey(request.AdminKey)
	if err != nil {
		return nil, err
	}
	context, err := pcsc.Establish()
	if err != nil {
		return nil, fail("no_reader", "No card reader was found.")
	}
	defer context.Release()
	card, reader, err := connect(context, request.Reader)
	if err != nil {
		return nil, err
	}
	defer card.Close(true)
	delete(s.cache, reader)

	session, err := s.login(card, reader, key)
	if err != nil {
		return nil, err
	}
	newKey, err := gp.NewAdminKey()
	if err != nil {
		return nil, err
	}
	version, err := session.ReplaceKeys(newKey)
	newKeyHex := strings.ToUpper(hex.EncodeToString(newKey))
	if err != nil {
		// The card may have taken the keys even if the reply was lost, so the key goes back anyway.
		return nil, &Error{Code: "secure_uncertain", AdminKey: newKeyHex,
			Message: "Replacing the admin keys didn't finish cleanly. Keep this key in case the card accepted it: " + err.Error()}
	}
	if _, err := gp.Open(card, newKey); err != nil {
		return nil, &Error{Code: "secure_uncertain", AdminKey: newKeyHex,
			Message: "The card accepted new admin keys, but the check afterwards failed. Keep this key: " + err.Error()}
	}
	return &SecureResult{Reader: reader, AdminKey: newKeyHex, AdminKeyVersion: int(version)}, nil
}

// SelfTest proves the applet stores and returns bytes on a card. It sets a PIN and writes junk, so
// it's for test cards. A reload clears both.
func (s *Service) SelfTest(reader, pin string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	context, err := pcsc.Establish()
	if err != nil {
		return nil, err
	}
	defer context.Release()
	card, _, err := connect(context, reader)
	if err != nil {
		return nil, err
	}
	defer card.Close(true)
	delete(s.cache, reader)

	var log []string
	applet, ok, err := gp.SelectApplet(card)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("the applet isn't on this card")
	}
	log = append(log, "selected applet "+applet.Version())
	if !applet.PINSet {
		if err := gp.SetPIN(card, pin); err != nil {
			return log, err
		}
		log = append(log, "set PIN")
	}
	if err := gp.VerifyPIN(card, pin); err != nil {
		return log, err
	}
	log = append(log, "verified PIN")
	junk := make([]byte, 1000)
	for i := range junk {
		junk[i] = byte(i * 7)
	}
	if err := gp.WriteBackup(card, junk); err != nil {
		return log, err
	}
	log = append(log, "wrote and committed 1000 bytes")
	back, err := gp.ReadBackup(card)
	if err != nil {
		return log, err
	}
	if string(back) != string(junk) {
		return log, fmt.Errorf("read back %d different bytes", len(back))
	}
	log = append(log, "read them back unchanged")
	if err := gp.Wipe(card); err != nil {
		return log, err
	}
	log = append(log, "wiped")
	return log, nil
}
