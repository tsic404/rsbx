package policy

import (
	"debug/elf"
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// elfFixture is a real ELF metadata fixture with program headers and no
// section table; dependency discovery must not depend on optional sections.
func elfFixture(loader string, needed []string, runpath string, library bool) []byte {
	stringsData := []byte{0}
	var neededOffsets []uint64
	for _, name := range needed {
		neededOffsets = append(neededOffsets, uint64(len(stringsData)))
		stringsData = append(stringsData, name...)
		stringsData = append(stringsData, 0)
	}
	runpathOffset := uint64(len(stringsData))
	if runpath != "" {
		stringsData = append(stringsData, runpath...)
		stringsData = append(stringsData, 0)
	}
	dynamic := len(needed) != 0 || runpath != ""
	programs := 1
	if dynamic {
		programs++
	}
	if loader != "" {
		programs++
	}
	entries := len(needed) + 3
	if runpath != "" {
		entries++
	}
	dynamicOffset := 64 + 56*programs
	stringsOffset := dynamicOffset
	if dynamic {
		stringsOffset += 16 * entries
	}
	loaderOffset := stringsOffset + len(stringsData)
	size := loaderOffset
	if loader != "" {
		size += len(loader) + 1
	}
	data := make([]byte, size)
	copy(data, []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), 1})
	typeValue := elf.ET_EXEC
	if library {
		typeValue = elf.ET_DYN
	}
	binary.LittleEndian.PutUint16(data[16:], uint16(typeValue))
	binary.LittleEndian.PutUint16(data[18:], uint16(elf.EM_X86_64))
	binary.LittleEndian.PutUint32(data[20:], 1)
	binary.LittleEndian.PutUint64(data[32:], 64)
	binary.LittleEndian.PutUint16(data[52:], 64)
	binary.LittleEndian.PutUint16(data[54:], 56)
	binary.LittleEndian.PutUint16(data[56:], uint16(programs))
	program := func(index int, typ elf.ProgType, offset, length uint64) {
		entry := data[64+56*index:]
		binary.LittleEndian.PutUint32(entry, uint32(typ))
		binary.LittleEndian.PutUint32(entry[4:], uint32(elf.PF_R))
		binary.LittleEndian.PutUint64(entry[8:], offset)
		binary.LittleEndian.PutUint64(entry[16:], offset)
		binary.LittleEndian.PutUint64(entry[32:], length)
		binary.LittleEndian.PutUint64(entry[40:], length)
	}
	program(0, elf.PT_LOAD, 0, uint64(len(data)))
	index := 1
	if dynamic {
		program(index, elf.PT_DYNAMIC, uint64(dynamicOffset), uint64(16*entries))
		index++
		offset := dynamicOffset
		entry := func(tag elf.DynTag, value uint64) {
			binary.LittleEndian.PutUint64(data[offset:], uint64(tag))
			binary.LittleEndian.PutUint64(data[offset+8:], value)
			offset += 16
		}
		entry(elf.DT_STRTAB, uint64(stringsOffset))
		entry(elf.DT_STRSZ, uint64(len(stringsData)))
		for _, position := range neededOffsets {
			entry(elf.DT_NEEDED, position)
		}
		if runpath != "" {
			entry(elf.DT_RUNPATH, runpathOffset)
		}
		entry(elf.DT_NULL, 0)
	}
	if loader != "" {
		program(index, elf.PT_INTERP, uint64(loaderOffset), uint64(len(loader)+1))
		copy(data[loaderOffset:], loader)
	}
	copy(data[stringsOffset:], stringsData)
	return data
}

func writePolicyFile(t *testing.T, filename string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filename, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func canonicalPolicyFile(t *testing.T, filename string) string {
	t.Helper()
	real, err := filepath.EvalSymlinks(filename)
	if err != nil {
		t.Fatal(err)
	}
	return real
}

func TestELFRuntimeClosureIsConcreteAndTransitive(t *testing.T) {
	t.Setenv("LD_LIBRARY_PATH", "")
	dir := t.TempDir()
	program := filepath.Join(dir, "program")
	loader := filepath.Join(dir, "loader")
	first, second := filepath.Join(dir, "libfirst.so"), filepath.Join(dir, "libsecond.so")
	unrelated := filepath.Join(dir, "libunrelated.so")
	writePolicyFile(t, loader, elfFixture("", nil, "", true))
	writePolicyFile(t, second, elfFixture("", nil, "", true))
	writePolicyFile(t, first, elfFixture("", []string{"libsecond.so"}, "$ORIGIN", true))
	writePolicyFile(t, unrelated, elfFixture("", nil, "", true))
	writePolicyFile(t, program, elfFixture(loader, []string{"libfirst.so"}, "$ORIGIN", false))
	p, err := New([]string{program})
	if err != nil {
		t.Fatal(err)
	}
	assets := map[string]bool{}
	for _, filename := range p.RuntimePaths() {
		assets[filename] = true
		fi, err := os.Stat(filename)
		if err != nil || !fi.Mode().IsRegular() {
			t.Fatalf("runtime grant is not a concrete file: %s, %v", filename, err)
		}
	}
	for _, filename := range []string{loader, first, second} {
		real := canonicalPolicyFile(t, filename)
		if !assets[real] {
			t.Errorf("required runtime %s missing: %v", real, p.RuntimePaths())
		}
		if p.IsLocal(real) || p.IsAliasTarget(real) {
			t.Errorf("runtime dependency %s became an arbitrary local invocation", real)
		}
	}
	if assets[canonicalPolicyFile(t, unrelated)] || assets[dir] {
		t.Fatalf("unrelated host library/directory exposed: %v", p.RuntimePaths())
	}
}

func TestNestedRuntimeScriptsExposeMetadataWithoutExecuteGrant(t *testing.T) {
	dir := t.TempDir()
	native := filepath.Join(dir, "native")
	middle, alias := filepath.Join(dir, "middle"), filepath.Join(dir, "middle-alias")
	top := filepath.Join(dir, "top")
	writePolicyFile(t, native, elfFixture("", nil, "", false))
	writePolicyFile(t, middle, []byte("#!"+native+" --middle\n"))
	if err := os.Symlink(middle, alias); err != nil {
		t.Fatal(err)
	}
	writePolicyFile(t, top, []byte("#!"+alias+" --top\n"))
	p, err := New([]string{top})
	if err != nil {
		t.Fatal(err)
	}
	interpreter, args, ok := p.InterpreterFor(top)
	if !ok || interpreter != canonicalPolicyFile(t, middle) || !reflect.DeepEqual(args, []string{"--top"}) {
		t.Fatalf("top interpreter = %q %v, %v", interpreter, args, ok)
	}
	spelling, ok := p.InterpreterSpellingFor(top)
	if !ok || spelling != alias {
		t.Fatalf("literal interpreter spelling = %q, %v", spelling, ok)
	}
	interpreter, args, ok = p.InterpreterFor(alias)
	if !ok || interpreter != canonicalPolicyFile(t, native) || !reflect.DeepEqual(args, []string{"--middle"}) {
		t.Fatalf("runtime alias metadata = %q %v, %v", interpreter, args, ok)
	}
	if p.IsLocal(alias) || p.IsAliasTarget(alias) || p.IsAliasTarget(interpreter) {
		t.Fatal("queryable runtime script metadata widened execution policy")
	}
	args[0] = "modified"
	_, again, _ := p.InterpreterFor(alias)
	if !reflect.DeepEqual(again, []string{"--middle"}) {
		t.Fatal("caller mutated compiled shebang arguments")
	}
}

func TestEnvShebangCompilesExactCommandArgv(t *testing.T) {
	dir := t.TempDir()
	environment, command := filepath.Join(dir, "env"), filepath.Join(dir, "runtime")
	script := filepath.Join(dir, "script")
	writePolicyFile(t, environment, elfFixture("", nil, "", false))
	writePolicyFile(t, command, elfFixture("", nil, "", false))
	t.Setenv("PATH", dir)
	argument := "-S runtime --mode"
	writePolicyFile(t, script, []byte("#!"+environment+" "+argument+"\n"))
	p, err := New([]string{script})
	if err != nil {
		t.Fatal(err)
	}
	interpreter, args, ok := p.InterpreterFor(script)
	if !ok || interpreter != canonicalPolicyFile(t, environment) || !reflect.DeepEqual(args, []string{argument}) {
		t.Fatalf("kernel env hop = %q %v, %v", interpreter, args, ok)
	}
	interpreter, args, ok = p.EnvInterpreterFor(script)
	if !ok || interpreter != canonicalPolicyFile(t, command) || !reflect.DeepEqual(args, []string{"runtime", "--mode"}) {
		t.Fatalf("env command hop = %q %v, %v", interpreter, args, ok)
	}
	if p.IsAliasTarget(interpreter) || p.IsLocal(environment) {
		t.Fatal("env metadata granted arbitrary interpreter execution")
	}
}

func TestRuntimeAndAliasIdentityAreStartupSnapshots(t *testing.T) {
	dir := t.TempDir()
	first, second, alias := filepath.Join(dir, "first"), filepath.Join(dir, "second"), filepath.Join(dir, "alias")
	writePolicyFile(t, first, elfFixture("", nil, "", false))
	writePolicyFile(t, second, elfFixture("", nil, "", false))
	if err := os.Symlink(first, alias); err != nil {
		t.Fatal(err)
	}
	p, err := New([]string{alias})
	if err != nil {
		t.Fatal(err)
	}
	before := p.ExecPaths()
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, alias); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, p.ExecPaths()) || p.IsAliasTarget(canonicalPolicyFile(t, second)) {
		t.Fatal("alias target was re-resolved after policy construction")
	}
	before[0] = "/modified"
	for _, filename := range p.ExecPaths() {
		if strings.Contains(filename, "modified") {
			t.Fatal("caller mutated compiled executable paths")
		}
	}
}
