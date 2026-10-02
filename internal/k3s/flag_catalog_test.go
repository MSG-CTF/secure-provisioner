package k3s

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testFlagImage = "registry.example.invalid/challenges/web@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testFlagValue = "CTF{local_test_value}"
const testFlagJSON = `{"schema_version":1,"flags":[{"image":"` + testFlagImage + `","flag":"` + testFlagValue + `"}]}`

func TestFlagCatalogUsesExactDigestAndNeverLeaksValuesInErrors(t *testing.T) {
	catalog, err := ParseFlagCatalog([]byte(testFlagJSON))
	if err != nil {
		t.Fatal(err)
	}
	if flag, found := catalog.Flag(testFlagImage); !found || flag != testFlagValue {
		t.Fatal("exact image did not resolve its FLAG")
	}
	if _, found := catalog.Flag(strings.Replace(testFlagImage, "aaaaaaaa", "bbbbbbbb", 1)); found {
		t.Fatal("different digest inherited a FLAG")
	}
	if err := catalog.Require([]string{testFlagImage}); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Require([]string{"missing-image"}); err == nil || strings.Contains(err.Error(), testFlagValue) {
		t.Fatalf("missing required FLAG error = %v", err)
	}
	if err := (*FlagCatalog)(nil).Require([]string{testFlagImage}); err == nil {
		t.Fatal("nil catalog accepted required FLAG")
	}
}

func TestFlagCatalogRejectsMalformedAndDuplicateEntriesWithoutLeakingValues(t *testing.T) {
	for _, input := range []string{
		`{"schema_version":1,"flags":[{"image":"` + testFlagImage + `","flag":"` + testFlagValue + `"},{"image":"` + testFlagImage + `","flag":"other"}]}`,
		`{"schema_version":1,"flags":[{"image":"registry.example.invalid/challenge:latest","flag":"` + testFlagValue + `"}]}`,
		`{"schema_version":1,"flags":[{"image":"` + testFlagImage + `","flag":""}]}`,
		`{"schema_version":1,"flags":[{"image":"` + testFlagImage + `","flag":"` + testFlagValue + `","extra":1}]}`,
		`{"schema_version":1,"flags":[{"image":"` + testFlagImage + `","flag":"` + testFlagValue + `","flag":"other"}]}`,
		`{"schema_version":2,"flags":[]}`,
	} {
		_, err := ParseFlagCatalog([]byte(input))
		if err == nil || strings.Contains(err.Error(), testFlagValue) {
			t.Fatalf("invalid catalog error = %v", err)
		}
	}
}

func TestLoadFlagCatalogRejectsWorldReadableFileAndSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flags.json")
	if err := os.WriteFile(path, []byte(testFlagJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFlagCatalog(path); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadFlagCatalog(path); err == nil {
			t.Fatal("world-readable FLAG file accepted")
		}
	}
	link := filepath.Join(t.TempDir(), "flags-link.json")
	if err := os.Symlink(path, link); err == nil {
		if _, err := LoadFlagCatalog(link); err == nil {
			t.Fatal("FLAG file symlink accepted")
		}
	}
}
