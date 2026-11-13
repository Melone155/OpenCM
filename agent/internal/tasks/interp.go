package tasks

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// interpreter → supported GOOS values (must match server/src/jobs/interpreters.ts)
var supported = map[string][]string{
	"powershell": {"windows"},
	"cmd":        {"windows"},
	"bash":       {"linux", "darwin"},
	"zsh":        {"linux", "darwin"},
	"python":     {"windows", "linux", "darwin"},
}

func Supported(interpreter, goos string) bool {
	for _, o := range supported[interpreter] {
		if o == goos {
			return true
		}
	}
	return false
}

// scriptFile returns the file extension and the content as written to disk.
// Fixed preambles make console output UTF-8; the signed content itself is unchanged.
func scriptFile(interpreter, content string) (ext string, data []byte) {
	switch interpreter {
	case "powershell":
		pre := "$OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8\r\n"
		// UTF-8 BOM: Windows PowerShell 5.1 reads BOM-less files as ANSI.
		return ".ps1", append([]byte("\xEF\xBB\xBF"), []byte(pre+content)...)
	case "cmd":
		body := strings.ReplaceAll(strings.ReplaceAll(content, "\r\n", "\n"), "\n", "\r\n")
		return ".cmd", []byte("@chcp 65001 >nul\r\n" + body)
	case "bash":
		return ".sh", []byte(content)
	case "zsh":
		return ".zsh", []byte(content)
	case "python":
		return ".py", []byte(content)
	}
	return ".txt", []byte(content)
}

func systemBinary(rel string) string {
	if root := os.Getenv("SystemRoot"); root != "" {
		p := filepath.Join(root, rel)
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Base(rel)
}

func firstExisting(candidates ...string) string {
	for _, c := range candidates {
		if filepath.IsAbs(c) {
			if _, err := os.Stat(c); err == nil {
				return c
			}
			continue
		}
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// commandFor builds the interpreter invocation for a script file.
func commandFor(interpreter, file string) (string, []string, error) {
	switch interpreter {
	case "powershell":
		return systemBinary(`System32\WindowsPowerShell\v1.0\powershell.exe`),
			[]string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", file}, nil
	case "cmd":
		return systemBinary(`System32\cmd.exe`), []string{"/d", "/c", file}, nil
	case "bash":
		if p := firstExisting("/bin/bash", "/usr/bin/bash", "bash"); p != "" {
			return p, []string{file}, nil
		}
	case "zsh":
		if p := firstExisting("/bin/zsh", "/usr/bin/zsh", "zsh"); p != "" {
			return p, []string{file}, nil
		}
	case "python":
		if p := firstExisting("python3", "/usr/bin/python3", "/usr/local/bin/python3"); p != "" {
			return p, []string{file}, nil
		}
		if p := firstExisting("py"); p != "" { // Windows launcher
			return p, []string{"-3", file}, nil
		}
		if p := firstExisting("python"); p != "" {
			return p, []string{file}, nil
		}
	default:
		return "", nil, fmt.Errorf("unknown interpreter %q", interpreter)
	}
	return "", nil, fmt.Errorf("interpreter %q is not installed on this device", interpreter)
}

// paramEnv renders parameters as OPENCM_PARAM_<NAME> environment variables
// (never substituted into the script text).
func paramEnv(params map[string]any) []string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	env := make([]string, 0, len(keys))
	for _, k := range keys {
		var v string
		switch x := params[k].(type) {
		case string:
			v = x
		case bool:
			v = strconv.FormatBool(x)
		case float64:
			v = strconv.FormatFloat(x, 'f', -1, 64)
		default:
			v = fmt.Sprint(x)
		}
		// strip NUL bytes – not representable in an environment block
		env = append(env, "OPENCM_PARAM_"+strings.ToUpper(k)+"="+strings.ReplaceAll(v, "\x00", ""))
	}
	return env
}
