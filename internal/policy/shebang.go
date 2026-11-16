package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// env is only an intermediate dependency of this script. Resolving its command
// here never adds either env or that interpreter to the executable allowlist.
func envInterpreter(arguments []string) (string, []string, error) {
	if len(arguments) != 1 {
		return "", nil, fmt.Errorf("env shebang has no interpreter command")
	}
	argument := arguments[0]
	var words []string
	if strings.HasPrefix(argument, "-S ") || strings.HasPrefix(argument, "-S\t") {
		var err error
		words, err = splitEnvArguments(strings.TrimSpace(argument[2:]))
		if err != nil {
			return "", nil, err
		}
	} else if strings.HasPrefix(argument, "--split-string=") {
		var err error
		words, err = splitEnvArguments(strings.TrimPrefix(argument, "--split-string="))
		if err != nil {
			return "", nil, err
		}
	} else {
		// Without -S the kernel passes the optional shebang text as one argv
		// element, even when that text contains spaces.
		words = []string{argument}
	}
	pathVar := os.Getenv("PATH")
	for len(words) > 0 {
		word := words[0]
		words = words[1:]
		switch {
		case word == "--":
			if len(words) == 0 {
				return "", nil, fmt.Errorf("env shebang has no interpreter command")
			}
			word, words = words[0], words[1:]
		case word == "-i" || word == "--ignore-environment":
			pathVar = "/bin:/usr/bin"
			continue
		case word == "-u" || word == "--unset":
			if len(words) == 0 {
				return "", nil, fmt.Errorf("env shebang has an incomplete unset option")
			}
			if words[0] == "PATH" {
				pathVar = "/bin:/usr/bin"
			}
			words = words[1:]
			continue
		case strings.HasPrefix(word, "--unset="):
			if strings.TrimPrefix(word, "--unset=") == "PATH" {
				pathVar = "/bin:/usr/bin"
			}
			continue
		case strings.HasPrefix(word, "-"):
			return "", nil, fmt.Errorf("env shebang option %q cannot be resolved at startup", word)
		case strings.ContainsRune(word, '='):
			if strings.HasPrefix(word, "PATH=") {
				pathVar = strings.TrimPrefix(word, "PATH=")
			}
			continue
		}
		argv := make([]string, 1, 1+len(words))
		argv[0] = word
		argv = append(argv, words...)
		if filepath.IsAbs(word) {
			return filepath.Clean(word), argv, nil
		}
		if strings.ContainsRune(word, '/') {
			return "", nil, fmt.Errorf("env interpreter %q is not a fixed absolute path", word)
		}
		command := Resolve(word, pathVar)
		if command == "" {
			return "", nil, fmt.Errorf("env interpreter %q not found in PATH", word)
		}
		return command, argv, nil
	}
	return "", nil, fmt.Errorf("env shebang has no interpreter command")
}

// -S supports quoted arguments without running a shell. In particular, shell
// operators and command substitution are not evaluated by dependency discovery.
func splitEnvArguments(text string) ([]string, error) {
	var words []string
	var word strings.Builder
	quote := rune(0)
	escape, started := false, false
	flush := func() {
		if started {
			words = append(words, word.String())
			word.Reset()
			started = false
		}
	}
	for _, char := range text {
		if escape {
			word.WriteRune(char)
			escape, started = false, true
			continue
		}
		if char == '\\' && quote != '\'' {
			escape, started = true, true
			continue
		}
		if quote != 0 {
			if char == quote {
				quote = 0
			} else {
				word.WriteRune(char)
			}
			continue
		}
		if char == '\'' || char == '"' {
			quote, started = char, true
		} else if unicode.IsSpace(char) {
			flush()
		} else {
			word.WriteRune(char)
			started = true
		}
	}
	if quote != 0 || escape {
		return nil, fmt.Errorf("unterminated env -S argument")
	}
	flush()
	return words, nil
}
