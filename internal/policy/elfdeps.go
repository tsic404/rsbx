package policy

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
)

// Runtime ELF loading uses program headers, not optional section headers.
// Parsing PT_DYNAMIC also supports stripped executables with no section table.
func readDynamicImage(f *elf.File, image *elfImage) error {
	var dynamic *elf.Prog
	for _, program := range f.Progs {
		if program.Type == elf.PT_DYNAMIC {
			dynamic = program
			break
		}
	}
	if dynamic == nil {
		return nil
	}
	entrySize := 8
	if f.Class == elf.ELFCLASS64 {
		entrySize = 16
	}
	if dynamic.Filesz%uint64(entrySize) != 0 || dynamic.Filesz > 64<<20 {
		return fmt.Errorf("invalid ELF dynamic segment size")
	}
	data, err := io.ReadAll(dynamic.Open())
	if err != nil {
		return err
	}
	var tableAddress, tableSize uint64
	var needed, rpath, runpath []uint64
	terminated := false
	for offset := 0; offset+entrySize <= len(data); offset += entrySize {
		var tag, value uint64
		if entrySize == 16 {
			tag = f.ByteOrder.Uint64(data[offset:])
			value = f.ByteOrder.Uint64(data[offset+8:])
		} else {
			tag = uint64(f.ByteOrder.Uint32(data[offset:]))
			value = uint64(f.ByteOrder.Uint32(data[offset+4:]))
		}
		switch elf.DynTag(tag) {
		case elf.DT_NULL:
			terminated = true
		case elf.DT_STRTAB:
			tableAddress = value
		case elf.DT_STRSZ:
			tableSize = value
		case elf.DT_NEEDED:
			needed = append(needed, value)
		case elf.DT_RPATH:
			rpath = append(rpath, value)
		case elf.DT_RUNPATH:
			runpath = append(runpath, value)
		case elf.DT_FLAGS_1:
			image.flags1 |= value
		}
		if terminated {
			break
		}
	}
	if !terminated {
		return fmt.Errorf("unterminated ELF dynamic segment")
	}
	if len(needed)+len(rpath)+len(runpath) == 0 {
		return nil
	}
	var strings []byte
	for _, program := range f.Progs {
		if program.Type != elf.PT_LOAD || tableAddress < program.Vaddr {
			continue
		}
		offset := tableAddress - program.Vaddr
		if offset > program.Filesz || tableSize > program.Filesz-offset || tableSize > 64<<20 {
			continue
		}
		strings = make([]byte, int(tableSize))
		if _, err := program.ReadAt(strings, int64(offset)); err != nil {
			return err
		}
		break
	}
	if strings == nil {
		return fmt.Errorf("ELF dynamic string table is not backed by a load segment")
	}
	decode := func(offsets []uint64) ([]string, error) {
		out := make([]string, len(offsets))
		for index, offset := range offsets {
			if offset >= uint64(len(strings)) {
				return nil, fmt.Errorf("ELF dynamic string offset is outside its table")
			}
			text := strings[int(offset):]
			end := bytes.IndexByte(text, 0)
			if end < 0 {
				return nil, fmt.Errorf("unterminated ELF dynamic string")
			}
			out[index] = string(text[:end])
		}
		return out, nil
	}
	if image.needed, err = decode(needed); err != nil {
		return err
	}
	if image.rpath, err = decode(rpath); err != nil {
		return err
	}
	image.runpath, err = decode(runpath)
	return err
}
