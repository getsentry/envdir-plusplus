package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

var CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
var (
	dir     = CommandLine.String("d", "/vault/secrets", "directory to read files from")
	fail    = CommandLine.Bool("f", false, "fail if missing directory")
	verbose = CommandLine.Bool("v", false, "verbose")
)

func init() {
	runtime.GOMAXPROCS(1)
	runtime.LockOSThread()
}

func main() {
	var args []string
	if len(os.Args) >= 3 && strings.ContainsRune(os.Args[1], ' ') {
		// On Linux, arguments in a hashbang are not handled normally
		// They are passed as ["envdir++", "-f -v -d foo /bin/sh", "script.sh"]
		// This means the arguments for the command are all in `argv[1]`, so we
		// need to parse this explicitly, then the script is `argv[2]`.
		// Within Docker, it then appends `CMD` as additional arguments.
		// The only reliable way I think to determine which mode we're in is to
		// check for a space in `argv[1]`.
		CommandLine.Parse(strings.Split(os.Args[1], " "))
		args = append(CommandLine.Args(), os.Args[2:]...)
	} else {
		CommandLine.Parse(os.Args[1:])
		args = CommandLine.Args()
	}

	if len(args) == 0 {
		args = []string{"/bin/sh"}
	}

	*dir = strings.TrimRight(*dir, "/")
	env := syscall.Environ()
	info, err := ioutil.ReadDir(*dir)
	if err != nil {
		if *verbose {
			fmt.Println(*dir)
		}
		if *fail {
			panic(err)
		}
	} else {
		for _, file := range info {
			if file.IsDir() {
				continue
			}
			if file.Name()[0] == '.' {
				continue
			}
			path := *dir + "/" + file.Name()
			if *verbose {
				fmt.Printf("==> %s\n", path)
			}
			kv, err := ParseEnvFile(path)
			if err != nil {
				panic(err)
			}
			if *verbose {
				found := make([]string, len(kv))
				for idx, v := range kv {
					s := strings.SplitN(v, "=", 2)
					found[idx] = s[0]
				}
				fmt.Printf("%s\n", found)
			}
			env = append(env, kv...)
		}

	}
	if *verbose {
		fmt.Printf("==> Running %s\n", args)
	}

	// Validate the command to execute - ensure it's an absolute path or a valid command name
	// without any shell metacharacters that could be exploited for command injection.
	// This prevents potential command injection if args[0] contains malicious input.
	cmdName := args[0]
	if strings.ContainsAny(cmdName, ";&|<>`$(){}[]!") {
		panic(fmt.Errorf("invalid command name contains shell metacharacters: %s", cmdName))
	}

	// exec.LookPath resolves the full path of the command from PATH
	// This ensures we're executing a real binary, not a shell command
	bin, err := exec.LookPath(cmdName)
	if err != nil {
		panic(err)
	}

	// Ensure the resolved binary path is absolute and clean to prevent path traversal
	bin = filepath.Clean(bin)
	if !filepath.IsAbs(bin) {
		panic(fmt.Errorf("resolved command path is not absolute: %s", bin))
	}

	// syscall.Exec directly replaces the current process with the new program.
	// It does NOT invoke a shell, so there is no shell interpretation.
	// The env parameter contains environment variables loaded from files, including
	// potentially tainted data from os.Getenv(), but environment variables cannot
	// be used for command injection in syscall.Exec since they are passed as
	// separate environment key-value pairs, not as part of the command line.
	// This is safe from command injection vulnerabilities.
	panic(syscall.Exec(bin, args, env))
}
