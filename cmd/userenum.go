package cmd

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ropnop/kerbrute/util"
	"github.com/spf13/cobra"
)

var userEnumCommand = &cobra.Command{
	Use:   "userenum [flags] <username_wordlist>",
	Short: "Enumerate valid domain usernames via Kerberos",
	Long: `Will enumerate valid usernames from a list by constructing AS-REQs to requesting a TGT from the KDC.
If no domain controller is specified, the tool will attempt to look one up via DNS SRV records.
A full domain is required. This domain will be capitalized and used as the Kerberos realm when attempting the bruteforce.
Valid usernames are displayed on stdout. With -o, a sorted, lowercase list of unique usernames is written to the output file.`,
	Args:   cobra.ExactArgs(1),
	PreRun: setupSession,
	RunE:   userEnum,
}

type enumResults struct {
	mu    sync.Mutex
	users map[string]struct{}
}

func (r *enumResults) add(username string) bool {
	username = strings.ToLower(username)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.users[username]; exists {
		return false
	}
	r.users[username] = struct{}{}
	return true
}

func (r *enumResults) writeFile(path string) error {
	r.mu.Lock()
	users := make([]string, 0, len(r.users))
	for username := range r.users {
		users = append(users, username)
	}
	r.mu.Unlock()
	sort.Strings(users)
	content := ""
	if len(users) > 0 {
		content = strings.Join(users, "\n") + "\n"
	}
	if err := ioutil.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("write username list %q: %w", path, err)
	}
	return nil
}

func init() {
	rootCmd.AddCommand(userEnumCommand)
}

func userEnum(cmd *cobra.Command, args []string) error {
	return runUserEnum(args, kSession.TestUsername)
}

func runUserEnum(args []string, probe func(string) (bool, error)) error {
	if threads < 1 {
		return fmt.Errorf("threads must be at least one")
	}
	usernamelist := args[0]
	usersChan := make(chan string, threads)
	results := &enumResults{users: make(map[string]struct{})}
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(threads)

	var scanner *bufio.Scanner
	if usernamelist != "-" {
		file, err := os.Open(usernamelist)
		if err != nil {
			return fmt.Errorf("open username list %q: %w", usernamelist, err)
		}
		defer file.Close()
		if logFileName != "" {
			outputInfo, err := os.Stat(logFileName)
			if err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("inspect username output %q: %w", logFileName, err)
			}
			if err == nil {
				inputInfo, err := file.Stat()
				if err != nil {
					return fmt.Errorf("inspect username list %q: %w", usernamelist, err)
				}
				if os.SameFile(inputInfo, outputInfo) {
					return fmt.Errorf("username output must not overwrite the input list")
				}
				if outputInfo.IsDir() {
					return fmt.Errorf("username output %q is a directory", logFileName)
				}
			}
		}
		scanner = bufio.NewScanner(file)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	for i := 0; i < threads; i++ {
		go makeEnumWorker(ctx, usersChan, &wg, results, probe)
	}

	start := time.Now()

Scan:
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			break Scan
		default:
			usernameline := scanner.Text()
			username, err := util.FormatUsername(usernameline)
			if err != nil {
				logger.Log.Debugf("[!] %q - %v", usernameline, err.Error())
				continue
			}
			if username == "" {
				logger.Log.Debugf("[!] %q - empty username", usernameline)
				continue
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
			select {
			case usersChan <- username:
			case <-ctx.Done():
				break Scan
			}
		}
	}
	close(usersChan)
	wg.Wait()

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read username list: %w", err)
	}
	if ctx.Err() != nil {
		return fmt.Errorf("username enumeration stopped before completion")
	}

	if logFileName != "" {
		if err := results.writeFile(logFileName); err != nil {
			return err
		}
	}

	finalCount := atomic.LoadInt32(&counter)
	finalSuccess := atomic.LoadInt32(&successes)
	logger.Log.Infof("Done! Tested %d usernames (%d valid) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())
	return nil
}
