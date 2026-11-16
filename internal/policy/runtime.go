package policy

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type scriptInterpreter struct {
	path     string
	spelling string
	args     []string
}

type elfImage struct {
	machine elf.Machine
	class   elf.Class
	data    elf.Data
	loader  string
	needed  []string
	rpath   []string
	runpath []string
	flags1  uint64
	script  *scriptInterpreter
}

type dependencyCompiler struct {
	policy       *Policy
	runtime      map[string]bool
	images       map[string]*elfImage
	visited      map[string]bool
	scriptActive map[string]bool
	cache        map[string][]string
	cacheLoaded  bool
	muslSearch   map[string][]string
}

func compile(local []string) (*Policy, error) {
	p := &Policy{
		Local:           append([]string(nil), local...),
		localSet:        make(map[string]bool, len(local)),
		execSet:         make(map[string]bool, len(local)),
		interpreters:    map[string]scriptInterpreter{},
		envInterpreters: map[string]scriptInterpreter{},
		aliases:         map[string]string{},
	}
	for _, filename := range local {
		p.localSet[filename] = true
		aliases, real, err := executableAliases(filename)
		if err != nil {
			return nil, err
		}
		for _, alias := range aliases {
			p.execSet[alias] = true
			p.aliases[alias] = real
		}
	}
	p.execPaths = sortedPaths(p.execSet)
	c := dependencyCompiler{
		policy: p, runtime: map[string]bool{}, images: map[string]*elfImage{},
		visited: map[string]bool{}, scriptActive: map[string]bool{},
		muslSearch: map[string][]string{},
	}
	for _, filename := range p.execPaths {
		if err := c.inspect(filename, nil, ""); err != nil {
			return nil, fmt.Errorf("runtime for %q: %w", filename, err)
		}
	}
	for filename := range p.execSet {
		delete(c.runtime, filename)
	}
	p.runtimePaths = sortedPaths(c.runtime)
	return p, nil
}

func sortedPaths(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for filename := range set {
		out = append(out, filename)
	}
	sort.Strings(out)
	return out
}

// executableAliases records both the configured spelling and aliases reached
// through parent-directory links. No containing directory becomes an asset.
func executableAliases(filename string) ([]string, string, error) {
	seen := map[string]bool{}
	current := filepath.Clean(filename)
	for range 40 {
		if seen[current] {
			return nil, "", fmt.Errorf("symlink cycle at %q", current)
		}
		seen[current] = true
		parent, err := filepath.EvalSymlinks(filepath.Dir(current))
		if err != nil {
			return nil, "", err
		}
		canonicalParent := filepath.Join(parent, filepath.Base(current))
		seen[canonicalParent] = true
		fi, err := os.Lstat(canonicalParent)
		if err != nil {
			return nil, "", err
		}
		if fi.Mode()&os.ModeSymlink == 0 {
			if !fi.Mode().IsRegular() {
				return nil, "", fmt.Errorf("runtime asset %q is not a regular file", filename)
			}
			return sortedPaths(seen), canonicalParent, nil
		}
		target, err := os.Readlink(canonicalParent)
		if err != nil {
			return nil, "", err
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(parent, target)
		}
		current = filepath.Clean(target)
	}
	return nil, "", fmt.Errorf("too many symlinks at %q", filename)
}

func (c *dependencyCompiler) addRuntime(filename string) (string, error) {
	if !filepath.IsAbs(filename) {
		return "", fmt.Errorf("runtime asset %q is not absolute", filename)
	}
	aliases, real, err := executableAliases(filename)
	if err != nil {
		return "", err
	}
	for _, alias := range aliases {
		c.runtime[alias] = true
		c.policy.aliases[alias] = real
	}
	return real, nil
}

func readImage(filename string) (*elfImage, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var head [256]byte
	n, err := f.ReadAt(head[:], 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	image := &elfImage{}
	if n >= 2 && string(head[:2]) == "#!" {
		line := head[2:n]
		if end := bytes.IndexByte(line, '\n'); end >= 0 {
			line = line[:end]
		} else if n == len(head) {
			return nil, fmt.Errorf("shebang in %q exceeds the kernel limit", filename)
		}
		text := strings.Trim(string(line), " \t")
		end := strings.IndexAny(text, " \t")
		interpreter, argument := text, ""
		if end >= 0 {
			interpreter = text[:end]
			argument = strings.Trim(text[end:], " \t")
		}
		if !filepath.IsAbs(interpreter) {
			return nil, fmt.Errorf("shebang interpreter %q is not absolute", interpreter)
		}
		image.script = &scriptInterpreter{path: interpreter}
		if argument != "" {
			image.script.args = []string{argument}
		}
		return image, nil
	}
	if n < 4 || !bytes.Equal(head[:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return image, nil
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	image.machine, image.class, image.data = ef.Machine, ef.Class, ef.Data
	for _, prog := range ef.Progs {
		if prog.Type != elf.PT_INTERP {
			continue
		}
		if prog.Filesz == 0 || prog.Filesz > 4096 {
			return nil, fmt.Errorf("invalid ELF interpreter length in %q", filename)
		}
		loader, err := io.ReadAll(prog.Open())
		if err != nil {
			return nil, err
		}
		image.loader = strings.TrimRight(string(loader), "\x00")
		if !filepath.IsAbs(image.loader) {
			return nil, fmt.Errorf("ELF interpreter %q is not absolute", image.loader)
		}
	}
	if err := readDynamicImage(ef, image); err != nil {
		return nil, err
	}
	return image, nil
}

func (c *dependencyCompiler) image(filename string) (*elfImage, error) {
	if image, ok := c.images[filename]; ok {
		return image, nil
	}
	image, err := readImage(filename)
	if err == nil {
		c.images[filename] = image
	}
	return image, err
}

func (c *dependencyCompiler) inspect(filename string, inherited []string, loader string) error {
	_, real, err := executableAliases(filename)
	if err != nil {
		return err
	}
	image, err := c.image(real)
	if err != nil {
		return err
	}
	var interpreter, envCommand string
	if image.script != nil {
		interpreter, err = c.addRuntime(image.script.path)
		if err != nil {
			return err
		}
		c.policy.interpreters[real] = scriptInterpreter{path: interpreter, spelling: image.script.path, args: image.script.args}
		if filepath.Base(interpreter) == "env" {
			command, argv, err := envInterpreter(image.script.args)
			if err != nil {
				return err
			}
			envCommand, err = c.addRuntime(command)
			if err != nil {
				return err
			}
			c.policy.envInterpreters[real] = scriptInterpreter{path: envCommand, args: argv}
		}
		if c.scriptActive[real] {
			return fmt.Errorf("recursive shebang interpreter at %q", real)
		}
	}
	if image.loader != "" {
		loader = image.loader
	}
	key := real + "\x00" + loader + "\x00" + strings.Join(inherited, "\x00")
	if c.visited[key] {
		return nil
	}
	c.visited[key] = true
	if image.script != nil {
		c.scriptActive[real] = true
		defer delete(c.scriptActive, real)
		if err := c.inspect(interpreter, nil, ""); err != nil {
			return err
		}
		if envCommand != "" {
			return c.inspect(envCommand, nil, "")
		}
		return nil
	}
	if image.loader != "" {
		interpreter, err := c.addRuntime(image.loader)
		if err != nil {
			return err
		}
		if err := c.inspect(interpreter, nil, loader); err != nil {
			return err
		}
	}
	if len(image.needed) == 0 {
		return nil
	}
	ownRpath, err := expandSearchPaths(image.rpath, real, image)
	if err != nil {
		return err
	}
	ownRunpath, err := expandSearchPaths(image.runpath, real, image)
	if err != nil {
		return err
	}
	var rpaths []string
	if len(image.runpath) == 0 {
		rpaths = append(rpaths, ownRpath...)
	}
	rpaths = append(rpaths, inherited...)
	unique := rpaths[:0]
	for _, directory := range rpaths {
		found := false
		for _, existing := range unique {
			if existing == directory {
				found = true
				break
			}
		}
		if !found {
			unique = append(unique, directory)
		}
	}
	rpaths = unique
	search := append([]string(nil), rpaths...)
	environment, err := expandSearchPaths([]string{os.Getenv("LD_LIBRARY_PATH")}, real, image)
	if err != nil {
		return err
	}
	search = append(search, environment...)
	search = append(search, ownRunpath...)
	musl := strings.Contains(filepath.Base(loader), "ld-musl-")
	if musl {
		directories, exists := c.muslSearch[loader]
		if !exists {
			configuration := "/etc/" + strings.TrimSuffix(filepath.Base(loader), ".so.1") + ".path"
			data, err := os.ReadFile(configuration)
			if err == nil {
				if _, err := c.addRuntime(configuration); err != nil {
					return err
				}
				directories = strings.FieldsFunc(string(data), func(r rune) bool { return r == ':' || r == '\n' })
			} else if !os.IsNotExist(err) {
				return err
			} else {
				directories = []string{"/lib", "/usr/local/lib", "/usr/lib"}
			}
			c.muslSearch[loader] = directories
		}
		search = append(search, directories...)
	} else if err := c.loadCache(); err != nil {
		return err
	}
	for _, needed := range image.needed {
		libraries, err := c.resolveLibrary(needed, search, image, !musl)
		if err != nil {
			return fmt.Errorf("%q needs %q: %w", real, needed, err)
		}
		for _, library := range libraries {
			if _, err := c.addRuntime(library); err != nil {
				return err
			}
			if err := c.inspect(library, rpaths, loader); err != nil {
				return err
			}
		}
	}
	return nil
}

func expandSearchPaths(values []string, filename string, image *elfImage) ([]string, error) {
	var out []string
	lib, platform := "lib", ""
	switch image.machine {
	case elf.EM_X86_64:
		lib, platform = "lib64", "x86_64"
	case elf.EM_386:
		platform = "i686"
	case elf.EM_AARCH64:
		lib, platform = "lib", "aarch64"
	case elf.EM_ARM:
		platform = "arm"
	case elf.EM_RISCV:
		platform = "riscv64"
	}
	replace := strings.NewReplacer("${ORIGIN}", filepath.Dir(filename), "$ORIGIN", filepath.Dir(filename), "${LIB}", lib, "$LIB", lib, "${PLATFORM}", platform, "$PLATFORM", platform)
	for _, value := range values {
		if value == "" {
			continue
		}
		for _, directory := range filepath.SplitList(value) {
			directory = replace.Replace(directory)
			if !filepath.IsAbs(directory) || strings.ContainsRune(directory, '$') {
				return nil, fmt.Errorf("runtime library search path %q cannot be resolved as a fixed host asset", directory)
			}
			out = append(out, filepath.Clean(directory))
		}
	}
	return out, nil
}

func (c *dependencyCompiler) resolveLibrary(name string, search []string, image *elfImage, cache bool) ([]string, error) {
	if strings.ContainsRune(name, '/') {
		if !filepath.IsAbs(name) {
			return nil, fmt.Errorf("relative DT_NEEDED path %q is not a fixed runtime asset", name)
		}
		if c.compatible(name, image) {
			return []string{filepath.Clean(name)}, nil
		}
		return nil, fmt.Errorf("incompatible or missing library %q", name)
	}
	for _, directory := range search {
		if variants := c.libraryVariants(directory, name, image, cache); len(variants) != 0 {
			return variants, nil
		}
	}
	if cache {
		var variants []string
		for _, candidate := range c.cache[name] {
			if c.compatible(candidate, image) {
				variants = append(variants, candidate)
			}
		}
		if len(variants) != 0 {
			return variants, nil
		}
	}
	if cache && image.flags1&uint64(elf.DF_1_NODEFLIB) == 0 {
		for _, directory := range defaultLibraryDirs(image) {
			if variants := c.libraryVariants(directory, name, image, true); len(variants) != 0 {
				return variants, nil
			}
		}
	}
	return nil, fmt.Errorf("library is not present in the host loader search path")
}

// Hardware-capability alternatives are still concrete files for the same
// required soname. Their directories and unrelated libraries remain remote.
func (c *dependencyCompiler) libraryVariants(directory, name string, image *elfImage, hardware bool) []string {
	var files []string
	if hardware {
		if variants, err := os.ReadDir(filepath.Join(directory, "glibc-hwcaps")); err == nil {
			for _, variant := range variants {
				if variant.IsDir() {
					candidate := filepath.Join(directory, "glibc-hwcaps", variant.Name(), name)
					if c.compatible(candidate, image) {
						files = append(files, candidate)
					}
				}
			}
		}
	}
	candidate := filepath.Join(directory, name)
	if c.compatible(candidate, image) {
		files = append(files, candidate)
	}
	return files
}

func (c *dependencyCompiler) compatible(filename string, want *elfImage) bool {
	_, real, err := executableAliases(filename)
	if err != nil {
		return false
	}
	image, err := c.image(real)
	return err == nil && image.machine == want.machine && image.class == want.class && image.data == want.data
}

func defaultLibraryDirs(image *elfImage) []string {
	var triplets []string
	switch image.machine {
	case elf.EM_X86_64:
		triplets = []string{"x86_64-linux-gnu"}
	case elf.EM_386:
		triplets = []string{"i386-linux-gnu"}
	case elf.EM_AARCH64:
		triplets = []string{"aarch64-linux-gnu"}
	case elf.EM_ARM:
		triplets = []string{"arm-linux-gnueabihf", "arm-linux-gnueabi"}
	case elf.EM_RISCV:
		triplets = []string{"riscv64-linux-gnu"}
	case elf.EM_PPC64:
		triplets = []string{"powerpc64le-linux-gnu", "powerpc64-linux-gnu"}
	case elf.EM_S390:
		triplets = []string{"s390x-linux-gnu"}
	}
	out := make([]string, 0, 2*len(triplets)+4)
	for _, triplet := range triplets {
		out = append(out, "/lib/"+triplet, "/usr/lib/"+triplet)
	}
	if image.class == elf.ELFCLASS64 {
		out = append(out, "/lib64", "/usr/lib64")
	}
	return append(out, "/lib", "/usr/lib")
}
