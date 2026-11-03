package windowsruntime

import (
	"encoding/binary"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// BuildRDPProfile validates the broker's RDP file and emits a UTF-16LE profile
// with a BOM. Only its verified address, account and safe display settings are
// retained; credentials, gateways, shells and unknown properties are rejected.
// Device redirection and security properties are replaced by fixed safe values.
// prompt is true for an operator download and false for Runtime stdin logon.
func BuildRDPProfile(c Connection, prompt bool) ([]byte, error) {
	invalid := func() ([]byte, error) { return nil, errors.New("invalid or unsafe broker RDP profile") }
	if c.Protocol != "rdp" || net.ParseIP(c.Host) == nil || c.Port < 1 || c.Port > 65535 || c.Username == "" || len(c.Username) > 256 || len(c.RDPFile) == 0 || len(c.RDPFile) > 16<<10 || !utf8.ValidString(c.RDPFile) {
		return invalid()
	}
	text := strings.TrimPrefix(c.RDPFile, "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	if strings.IndexFunc(text, func(r rune) bool { return unicode.IsControl(r) && r != '\n' }) >= 0 {
		return invalid()
	}
	properties := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || parts[0] == "" || parts[0] != strings.TrimSpace(parts[0]) {
			return invalid()
		}
		name := strings.ToLower(parts[0])
		if _, duplicate := properties[name]; duplicate {
			return invalid()
		}
		value := parts[2]
		switch name {
		case "full address", "username":
			if parts[1] != "s" || value == "" || value != strings.TrimSpace(value) {
				return invalid()
			}
		case "drivestoredirect":
			if parts[1] != "s" || value != "" {
				return invalid()
			}
		default:
			min, max, known := rdpProfileIntegerBounds(name)
			if !known || parts[1] != "i" {
				return invalid()
			}
			n, err := strconv.Atoi(value)
			if err != nil || n < min || n > max {
				return invalid()
			}
			if name == "session bpp" && n != 16 && n != 24 && n != 32 {
				return invalid()
			}
			value = strconv.Itoa(n)
		}
		properties[name] = value
	}
	address, ok := properties["full address"]
	if !ok {
		return invalid()
	}
	user, ok := properties["username"]
	if !ok || user != c.Username {
		return invalid()
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return invalid()
	}
	ip := net.ParseIP(host)
	port, err := strconv.Atoi(portText)
	if ip == nil || err != nil || port != c.Port || !ip.Equal(net.ParseIP(c.Host)) {
		return invalid()
	}
	lines := []string{"full address:s:" + net.JoinHostPort(ip.String(), strconv.Itoa(port)), "username:s:" + user}
	// These values cannot be weakened by the broker file. The Runtime adds its
	// one execution drive separately through the FreeRDP command line.
	// authentication level 1 rejects failed server authentication; level 2 would
	// offer an interactive override in a downloaded Windows client profile.
	forced := []string{
		"authentication level:i:1", "enablecredsspsupport:i:1", "negotiate security layer:i:1",
		"redirectclipboard:i:0", "redirectprinters:i:0", "redirectcomports:i:0", "redirectsmartcards:i:0", "redirectposdevices:i:0", "redirectdrives:i:0", "drivestoredirect:s:",
		"autoreconnection enabled:i:0", "remoteapplicationmode:i:0", "audiomode:i:2", "audiocapturemode:i:0",
	}
	lines = append(lines, forced...)
	promptValue := "0"
	if prompt {
		promptValue = "1"
	}
	lines = append(lines, "prompt for credentials:i:"+promptValue)
	display := []string{}
	for _, name := range []string{"desktopwidth", "desktopheight", "screen mode id", "session bpp", "use multimon"} {
		if value, ok := properties[name]; ok {
			display = append(display, name+":i:"+value)
		}
	}
	sort.Strings(display)
	lines = append(lines, display...)
	units := utf16.Encode([]rune(strings.Join(lines, "\r\n") + "\r\n"))
	result := make([]byte, 2+2*len(units))
	result[0], result[1] = 0xff, 0xfe
	for i, unit := range units {
		binary.LittleEndian.PutUint16(result[2+2*i:], unit)
	}
	return result, nil
}

func rdpProfileIntegerBounds(name string) (int, int, bool) {
	switch name {
	case "desktopwidth":
		return 640, 8192, true
	case "desktopheight":
		return 480, 8192, true
	case "screen mode id":
		return 1, 2, true
	case "session bpp":
		return 16, 32, true
	case "authentication level":
		return 0, 3, true
	case "audiomode":
		return 0, 2, true
	case "use multimon", "prompt for credentials", "enablecredsspsupport", "negotiate security layer", "redirectclipboard", "redirectprinters", "redirectcomports", "redirectsmartcards", "redirectposdevices", "redirectdrives", "autoreconnection enabled", "remoteapplicationmode", "audiocapturemode":
		return 0, 1, true
	default:
		return 0, 0, false
	}
}
