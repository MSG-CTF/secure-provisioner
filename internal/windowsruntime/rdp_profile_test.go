package windowsruntime

import (
	"encoding/binary"
	"strings"
	"testing"
	"unicode/utf16"
)

func profileConnection() Connection {
	return Connection{Protocol: "rdp", Host: "203.0.113.10", Port: 3389, Username: "msgexec", RDPFile: "full address:s:203.0.113.10:3389\r\nusername:s:msgexec\r\nprompt for credentials:i:1\r\nenablecredsspsupport:i:1\r\nredirectclipboard:i:0\r\nredirectprinters:i:0\r\ndrivestoredirect:s:\r\n"}
}

func decodeProfileForTest(t *testing.T, raw []byte) string {
	t.Helper()
	if len(raw) < 2 || raw[0] != 0xff || raw[1] != 0xfe || len(raw)%2 != 0 {
		t.Fatal("profile must be UTF16LE with BOM")
	}
	units := make([]uint16, (len(raw)-2)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2+2*i:])
	}
	return string(utf16.Decode(units))
}

func TestBuildRDPProfileUsesBrokerFileWithSecureDefaults(t *testing.T) {
	c := profileConnection()
	c.RDPFile += "desktopwidth:i:1280\r\ndesktopheight:i:720\r\nauthentication level:i:0\r\nredirectcomports:i:1\r\nredirectsmartcards:i:1\r\n"
	for _, prompt := range []bool{true, false} {
		b, e := BuildRDPProfile(c, prompt)
		if e != nil {
			t.Fatal(e)
		}
		text := decodeProfileForTest(t, b)
		for _, want := range []string{"full address:s:203.0.113.10:3389\r\n", "username:s:msgexec\r\n", "desktopwidth:i:1280\r\n", "desktopheight:i:720\r\n", "authentication level:i:1\r\n", "enablecredsspsupport:i:1\r\n", "redirectclipboard:i:0\r\n", "redirectprinters:i:0\r\n", "redirectcomports:i:0\r\n", "redirectsmartcards:i:0\r\n", "drivestoredirect:s:\r\n", "autoreconnection enabled:i:0\r\n"} {
			if !strings.Contains(text, want) {
				t.Errorf("normalized profile missing %q", want)
			}
		}
		wantPrompt := "prompt for credentials:i:0\r\n"
		if prompt {
			wantPrompt = "prompt for credentials:i:1\r\n"
		}
		if !strings.Contains(text, wantPrompt) {
			t.Fatalf("prompt behavior missing: %q", wantPrompt)
		}
		for _, bad := range []string{"password", "gatewayhostname", "alternate shell", "redirectcomports:i:1", "redirectsmartcards:i:1"} {
			if strings.Contains(text, bad) {
				t.Errorf("unsafe setting retained %q", bad)
			}
		}
	}
}

func TestBuildRDPProfilePreservesUnicodeUserAndIPv6(t *testing.T) {
	c := profileConnection()
	c.Host = "2001:db8::1"
	c.Port = 3390
	c.Username = `DOMAIN\실행자`
	c.RDPFile = "full address:s:[2001:0db8::1]:3390\r\nusername:s:" + c.Username + "\r\n"
	b, e := BuildRDPProfile(c, true)
	if e != nil {
		t.Fatal(e)
	}
	text := decodeProfileForTest(t, b)
	if !strings.Contains(text, "full address:s:[2001:db8::1]:3390\r\n") || !strings.Contains(text, "username:s:DOMAIN\\실행자\r\n") {
		t.Fatal("profile lost the API target or Unicode account")
	}
}

func TestBuildRDPProfileRejectsMissingMismatchedAndUnsafeInput(t *testing.T) {
	for _, tc := range []struct{ name, file string }{
		{"empty", ""}, {"missing_user", "full address:s:203.0.113.10:3389\r\n"}, {"missing_address", "username:s:msgexec\r\n"},
		{"wrong_host", "full address:s:203.0.113.11:3389\r\nusername:s:msgexec\r\n"}, {"wrong_port", "full address:s:203.0.113.10:3390\r\nusername:s:msgexec\r\n"}, {"wrong_user", "full address:s:203.0.113.10:3389\r\nusername:s:other\r\n"},
		{"missing_port", "full address:s:203.0.113.10\r\nusername:s:msgexec\r\n"},
		{"duplicate_address", profileConnection().RDPFile + "FULL ADDRESS:s:203.0.113.10:3389\r\n"}, {"duplicate_user", profileConnection().RDPFile + "username:s:msgexec\r\n"}, {"duplicate_other", profileConnection().RDPFile + "redirectclipboard:i:0\r\n"},
		{"password", profileConnection().RDPFile + "password 51:b:secret\r\n"}, {"gateway", profileConnection().RDPFile + "gatewayhostname:s:evil.invalid\r\n"}, {"shell", profileConnection().RDPFile + "alternate shell:s:cmd.exe\r\n"}, {"unknown", profileConnection().RDPFile + "mystery:s:value\r\n"},
		{"drives", strings.ReplaceAll(profileConnection().RDPFile, "drivestoredirect:s:", "drivestoredirect:s:*")},
		{"malformed", profileConnection().RDPFile + "redirectcomports=1\r\n"}, {"wrong_type", strings.ReplaceAll(profileConnection().RDPFile, "username:s:", "username:i:")}, {"nul", profileConnection().RDPFile + "\x00"}, {"tab", profileConnection().RDPFile + "\t"}, {"bare_cr", profileConnection().RDPFile + "\rmalformed"}, {"oversized", strings.Repeat("x", 16385)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := profileConnection()
			c.RDPFile = tc.file
			if _, e := BuildRDPProfile(c, false); e == nil {
				t.Fatal("invalid broker RDP profile accepted")
			}
		})
	}
}
