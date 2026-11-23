// Modified by CSpanias on 2026-11-23.
package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ropnop/kerbrute/util"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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

func (r *enumResults) writeFile(ctx context.Context, path string) (retErr error) {
	r.mu.Lock()
	users := make([]string, 0, len(r.users))
	for username := range r.users {
		users = append(users, username)
	}
	r.mu.Unlock()
	sort.Strings(users)
	file, err := os.CreateTemp(filepath.Dir(path), ".kerbrute-users-*")
	if err != nil {
		return fmt.Errorf("write username list %q: %w", path, err)
	}
	defer func() {
		if err := os.Remove(file.Name()); err != nil && !os.IsNotExist(err) {
			retErr = errors.Join(retErr, fmt.Errorf("remove temporary output %q: %w", file.Name(), err))
		}
	}()
	writer := bufio.NewWriter(file)
	for _, username := range users {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("write username list %q: %w", path, errors.Join(err, file.Close()))
		}
		if _, err := fmt.Fprintln(writer, username); err != nil {
			return fmt.Errorf("write username list %q: %w", path, errors.Join(err, file.Close()))
		}
	}
	if err := writer.Flush(); err != nil {
		return fmt.Errorf("write username list %q: %w", path, errors.Join(err, file.Close()))
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("write username list %q: %w", path, err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("write username list %q: %w", path, err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
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

func runUserEnum(args []string, probe func(string) (bool, error)) (retErr error) {
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
	progressEnabled := term.IsTerminal(int(os.Stderr.Fd()))
	totalLines := int64(-1)
	if usernamelist != "-" {
		file, err := os.Open(usernamelist)
		if err != nil {
			return fmt.Errorf("open username list %q: %w", usernamelist, err)
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return fmt.Errorf("inspect username list %q: %w", usernamelist, err)
		}
		if logFileName != "" {
			for _, outputPath := range []string{logFileName, logFileName + ".partial"} {
				outputInfo, err := os.Stat(outputPath)
				if err != nil && !os.IsNotExist(err) {
					return fmt.Errorf("inspect username output %q: %w", outputPath, err)
				}
				if err == nil {
					if os.SameFile(info, outputInfo) {
						return fmt.Errorf("username output must not overwrite the input list")
					}
					if outputInfo.IsDir() {
						return fmt.Errorf("username output %q is a directory", outputPath)
					}
				}
			}
		}
		if progressEnabled && info.Mode().IsRegular() {
			fmt.Fprintln(os.Stderr, "Counting input lines for progress...")
			totalLines, err = countInputLines(ctx, file)
			if err != nil {
				return fmt.Errorf("count username input lines: %w", err)
			}
		}
		scanner = bufio.NewScanner(file)
	} else {
		scanner = bufio.NewScanner(os.Stdin)
	}

	seen, err := newEnumSeen()
	if err != nil {
		return err
	}
	defer func() {
		if seen != nil {
			retErr = errors.Join(retErr, seen.close())
		}
	}()

	for i := 0; i < threads; i++ {
		go makeEnumWorker(ctx, usersChan, &wg, results, probe)
	}

	start := time.Now()
	var skipped int64
	var stopProgress func()
	if progressEnabled {
		stopProgress = startEnumProgress(totalLines, &skipped, start)
	}
	lines := scanLines(ctx, scanner)

Scan:
	for {
		select {
		case <-ctx.Done():
			break Scan
		case line, ok := <-lines:
			if !ok {
				break Scan
			}
			if line.err != nil {
				retErr = fmt.Errorf("read username list: %w", line.err)
				cancel()
				break Scan
			}
			usernameline := line.line
			username, err := util.FormatUsername(usernameline)
			if err != nil {
				logger.Log.Debugf("[!] %q - %v", usernameline, err.Error())
				atomic.AddInt64(&skipped, 1)
				continue
			}
			if username == "" {
				logger.Log.Debugf("[!] %q - empty username", usernameline)
				atomic.AddInt64(&skipped, 1)
				continue
			}
			newUsername, err := seen.add(username)
			if err != nil {
				retErr = err
				cancel()
				break Scan
			}
			if !newUsername {
				atomic.AddInt64(&skipped, 1)
				continue
			}
			select {
			case usersChan <- username:
			case <-ctx.Done():
				break Scan
			}
		}
	}
	close(usersChan)
	wg.Wait()
	if stopProgress != nil {
		stopProgress()
	}
	retErr = errors.Join(retErr, seen.close())
	seen = nil

	if ctx.Err() != nil {
		if err := currentFailure(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("username enumeration stopped before completion: %w", err))
		} else {
			retErr = errors.Join(retErr, fmt.Errorf("username enumeration stopped before completion"))
		}
	}

	if logFileName != "" {
		outputPath := logFileName
		outputCtx := ctx
		if retErr != nil {
			outputPath += ".partial"
			outputCtx = context.Background()
		}
		if err := results.writeFile(outputCtx, outputPath); err != nil {
			retErr = errors.Join(retErr, err)
			if outputPath == logFileName {
				outputPath += ".partial"
				if err := results.writeFile(context.Background(), outputPath); err != nil {
					retErr = errors.Join(retErr, err)
				} else {
					logger.Log.Warningf("Incomplete username list saved to %s", outputPath)
				}
			}
		} else if retErr != nil {
			logger.Log.Warningf("Incomplete username list saved to %s", outputPath)
		}
	}

	if retErr != nil {
		return retErr
	}
	finalCount := atomic.LoadInt32(&counter)
	finalSuccess := atomic.LoadInt32(&successes)
	logger.Log.Infof("Done! Tested %d usernames (%d valid) in %.3f seconds", finalCount, finalSuccess, time.Since(start).Seconds())
	return nil
}
