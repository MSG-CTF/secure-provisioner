package k3s

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// FlagCatalog contains operator-owned values loaded only in the worker process.
// Values are never serialized into operations, image policies, or Deployments.
type FlagCatalog struct {
	flags map[string]string
}

type flagFile struct {
	SchemaVersion int `json:"schema_version"`
	Flags         []struct {
		Image string `json:"image"`
		Flag  string `json:"flag"`
	} `json:"flags"`
}

func LoadFlagCatalog(filename string) (*FlagCatalog, error) {
	contents, err := readTrustedFlagFile(filename)
	if err != nil {
		return nil, err
	}
	return ParseFlagCatalog(contents)
}

func ParseFlagCatalog(contents []byte) (*FlagCatalog, error) {
	if len(contents) > 1<<20 {
		return nil, errors.New("FLAG file exceeds 1 MiB")
	}
	if err := rejectDuplicateFlagKeys(json.NewDecoder(bytes.NewReader(contents))); err != nil {
		return nil, errors.New("invalid or duplicate FLAG file JSON")
	}
	var config flagFile
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, errors.New("invalid FLAG file JSON")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("FLAG file must contain one JSON object")
	}
	if config.SchemaVersion != 1 || config.Flags == nil {
		return nil, errors.New("FLAG file requires schema_version 1 and flags")
	}
	catalog := &FlagCatalog{flags: make(map[string]string, len(config.Flags))}
	for _, entry := range config.Flags {
		if !validFlagImage(entry.Image) || len(entry.Flag) > 4096 ||
			!utf8.ValidString(entry.Flag) || strings.TrimSpace(entry.Flag) == "" ||
			strings.ContainsAny(entry.Flag, "\x00\r\n") {
			return nil, errors.New("FLAG file contains an invalid image or value")
		}
		if _, exists := catalog.flags[entry.Image]; exists {
			return nil, errors.New("FLAG file contains a duplicate image")
		}
		catalog.flags[entry.Image] = entry.Flag
	}
	return catalog, nil
}

func rejectDuplicateFlagKeys(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON field")
			}
			folded := strings.ToLower(key)
			if _, exists := seen[folded]; exists {
				return errors.New("duplicate JSON field")
			}
			seen[folded] = struct{}{}
			if err := rejectDuplicateFlagKeys(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := rejectDuplicateFlagKeys(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func validFlagImage(image string) bool {
	repository, digest, found := strings.Cut(image, "@sha256:")
	if !found || repository == "" || repository != strings.ToLower(repository) ||
		strings.ContainsAny(repository, "@: \t\r\n") || len(digest) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(digest)
	return err == nil && len(decoded) == 32 && digest == strings.ToLower(digest)
}

func (catalog *FlagCatalog) Flag(image string) (string, bool) {
	if catalog == nil {
		return "", false
	}
	flag, found := catalog.flags[image]
	return flag, found
}

func (catalog *FlagCatalog) Require(images []string) error {
	for _, image := range images {
		if _, found := catalog.Flag(image); !found {
			return errors.New("required FLAG is not configured")
		}
	}
	return nil
}

func (catalog *FlagCatalog) Images() []string {
	if catalog == nil {
		return nil
	}
	images := make([]string, 0, len(catalog.flags))
	for image := range catalog.flags {
		images = append(images, image)
	}
	return images
}
