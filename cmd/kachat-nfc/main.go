// Command kachat-nfc writes the KaChat-NFC applet to a smart card and serves the local helper that
// Kaspa Quick Start's panel talks to.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/KaspaSilver/KaChat-NFC/internal/helper"
)

// Set at build time.
var version = "dev"

const usage = `kachat-nfc %s

  kachat-nfc status                   Show readers and cards as JSON
  kachat-nfc load [--confirm-erase]   Write the KaChat-NFC applet to the card
  kachat-nfc secure                   Replace the card's admin keys and print the new key
  kachat-nfc selftest --pin PIN       Prove the applet stores data. Test cards only
  kachat-nfc serve                    Run the local helper for Kaspa Quick Start
  kachat-nfc version                  Print the version

load and secure take --reader NAME and --admin-key HEX. serve takes --listen ADDRESS,
--allow-origin URL (comma separated) and --internal.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	service := helper.NewService(version)
	var err error
	switch os.Args[1] {
	case "version":
		fmt.Println(version)
	case "status":
		var status *helper.Status
		if status, err = service.Status(); err == nil {
			printJSON(status)
		}
	case "load":
		err = runLoad(service, os.Args[2:])
	case "secure":
		err = runSecure(service, os.Args[2:])
	case "selftest":
		err = runSelfTest(service, os.Args[2:])
	case "serve":
		err = runServe(service, os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	if err != nil {
		var problem *helper.Error
		if errors.As(err, &problem) {
			printJSON(map[string]any{"error": problem})
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
		}
		os.Exit(1)
	}
}

func printJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.Encode(value)
}

func runLoad(service *helper.Service, args []string) error {
	flags := flag.NewFlagSet("load", flag.ExitOnError)
	reader := flags.String("reader", "", "reader name, if more than one card is in")
	adminKey := flags.String("admin-key", "", "the card's admin key, if it isn't the default")
	confirmErase := flags.Bool("confirm-erase", false, "allow reloading a card, erasing its PIN and backup")
	flags.Parse(args)
	result, err := service.Load(helper.LoadRequest{Reader: *reader, AdminKey: *adminKey, ConfirmErase: *confirmErase})
	if err != nil {
		return err
	}
	printJSON(result)
	return nil
}

func runSecure(service *helper.Service, args []string) error {
	flags := flag.NewFlagSet("secure", flag.ExitOnError)
	reader := flags.String("reader", "", "reader name, if more than one card is in")
	adminKey := flags.String("admin-key", "", "the card's admin key, if it isn't the default")
	flags.Parse(args)
	result, err := service.Secure(helper.SecureRequest{Reader: *reader, AdminKey: *adminKey})
	if err != nil {
		return err
	}
	printJSON(result)
	return nil
}

func runSelfTest(service *helper.Service, args []string) error {
	flags := flag.NewFlagSet("selftest", flag.ExitOnError)
	reader := flags.String("reader", "", "reader name, if more than one card is in")
	pin := flags.String("pin", "", "6 to 16 characters. Set on the card if it has no PIN yet")
	flags.Parse(args)
	if len(*pin) < 6 || len(*pin) > 16 {
		return errors.New("--pin must be 6 to 16 characters")
	}
	log, err := service.SelfTest(*reader, *pin)
	for _, line := range log {
		fmt.Println(line)
	}
	return err
}

func runServe(service *helper.Service, args []string) error {
	flags := flag.NewFlagSet("serve", flag.ExitOnError)
	listen := flags.String("listen", helper.DefaultAddress, "address to listen on")
	origins := flags.String("allow-origin", "", "extra panel origins, comma separated")
	internal := flags.Bool("internal", false, "for a container on a private Docker network only")
	flags.Parse(args)
	server := &helper.Server{Service: service, Internal: *internal}
	for _, origin := range strings.Split(*origins, ",") {
		if origin = strings.TrimSpace(origin); origin != "" {
			server.AllowedOrigins = append(server.AllowedOrigins, origin)
		}
	}
	fmt.Fprintln(os.Stderr, "kachat-nfc helper", version, "listening on", *listen)
	return server.ListenAndServe(*listen)
}
