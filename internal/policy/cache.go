package policy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
)

// The cache is a concrete loader metadata asset, not a grant for the libraries
// it lists. Only DT_NEEDED names are resolved from it by the compiler.
func (c *dependencyCompiler) loadCache() error {
	if c.cacheLoaded {
		return nil
	}
	c.cacheLoaded = true
	data, err := os.ReadFile("/etc/ld.so.cache")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	c.cache, err = parseLoaderCache(data)
	if err != nil {
		return fmt.Errorf("host loader cache: %w", err)
	}
	_, err = c.addRuntime("/etc/ld.so.cache")
	return err
}

// glibc's old cache has 12-byte entries and string-table-relative offsets;
// version 1.1 has a 48-byte header, 24-byte entries and file-relative offsets.
// Compatibility caches embed the aligned version 1.1 header after old entries.
func parseLoaderCache(data []byte) (map[string][]string, error) {
	const modernMagic = "glibc-ld.so.cache1.1"
	const oldMagic = "ld.so-1.7.0"
	var order binary.ByteOrder = binary.NativeEndian
	start, entries, width, stringsAt, count := 0, 0, 0, 0, uint32(0)
	if bytes.HasPrefix(data, []byte(oldMagic)) {
		if len(data) < 16 {
			return nil, fmt.Errorf("truncated old header")
		}
		count = order.Uint32(data[12:16])
		if uint64(count)*12+16 > uint64(len(data)) {
			return nil, fmt.Errorf("invalid old entry count")
		}
		entries, width, stringsAt = 16, 12, 16+int(count)*12
		aligned := (stringsAt + 7) &^ 7
		if aligned <= len(data) && bytes.HasPrefix(data[aligned:], []byte(modernMagic)) {
			start = aligned
		}
	} else if !bytes.HasPrefix(data, []byte(modernMagic)) {
		return nil, fmt.Errorf("unrecognised cache format")
	}
	if bytes.HasPrefix(data[start:], []byte(modernMagic)) {
		if len(data)-start < 48 {
			return nil, fmt.Errorf("truncated version 1.1 header")
		}
		switch data[start+28] & 3 {
		case 1:
			return nil, fmt.Errorf("invalid cache byte order")
		case 2:
			order = binary.LittleEndian
		case 3:
			order = binary.BigEndian
		}
		count = order.Uint32(data[start+20 : start+24])
		if uint64(count)*24+48 > uint64(len(data)-start) {
			return nil, fmt.Errorf("invalid version 1.1 entry count")
		}
		entries, width, stringsAt = start+48, 24, start
		length := order.Uint32(data[start+24 : start+28])
		if uint64(entries)+uint64(count)*24+uint64(length) > uint64(len(data)) {
			return nil, fmt.Errorf("truncated string table")
		}
	}
	stringAt := func(offset uint32) (string, bool) {
		absolute := uint64(stringsAt) + uint64(offset)
		if absolute >= uint64(len(data)) {
			return "", false
		}
		text := data[int(absolute):]
		end := bytes.IndexByte(text, 0)
		if end < 0 {
			return "", false
		}
		return string(text[:end]), true
	}
	out := map[string][]string{}
	for index := range count {
		entry := entries + int(index)*width
		name, validName := stringAt(order.Uint32(data[entry+4 : entry+8]))
		filename, validFile := stringAt(order.Uint32(data[entry+8 : entry+12]))
		if !validName || !validFile || name == "" || !filepath.IsAbs(filename) {
			return nil, fmt.Errorf("invalid cache string offset")
		}
		out[name] = append(out[name], filepath.Clean(filename))
	}
	return out, nil
}
