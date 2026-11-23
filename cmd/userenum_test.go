package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ropnop/gokrb5/v8/iana/errorcode"
	"github.com/ropnop/gokrb5/v8/messages"
	"github.com/ropnop/gokrb5/v8/types"
	"github.com/ropnop/kerbrute/util"
)

func setupEnumTest(t *testing.T, output string) {
	t.Helper()
	ctx, cancel = context.WithCancel(context.Background())
	domain = "example.test"
	logFileName = output
	threads = 8
	delay = 0
	atomic.StoreInt32(&counter, 0)
	atomic.StoreInt32(&successes, 0)
	failureMu.Lock()
	runFailure = nil
	failureMu.Unlock()
	logger = util.NewLogger(false, "")
}

func TestUserEnumWritesUniqueSortedUsernames(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	output := filepath.Join(dir, "users.txt")
	wordlist := "SAM\nadmin\nSam@example.test\ninvalid\nAdmin\nsam\n@domain.test\n"
	if err := ioutil.WriteFile(input, []byte(wordlist), 0600); err != nil {
		t.Fatal(err)
	}
	setupEnumTest(t, output)
	probe := func(username string) (bool, error) {
		return strings.EqualFold(username, "sam") || strings.EqualFold(username, "admin"), nil
	}
	if err := runUserEnum([]string{input}, probe); err != nil {
		t.Fatal(err)
	}
	got, err := ioutil.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "admin\nsam\n" {
		t.Fatalf("unexpected username output: %q", got)
	}
	if got := atomic.LoadInt32(&successes); got != 2 {
		t.Fatalf("got %d valid users, want 2", got)
	}
	if got := atomic.LoadInt32(&counter); got != 3 {
		t.Fatalf("tested %d usernames, want 3", got)
	}
}

func TestUserEnumWithKerberosResponses(t *testing.T) {
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, addr, err := listener.ReadFrom(buffer)
			if err != nil {
				return
			}
			var request messages.ASReq
			if err := request.Unmarshal(buffer[:n]); err != nil {
				t.Error(err)
				return
			}
			code := errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN
			if strings.EqualFold(request.ReqBody.CName.PrincipalNameString(), "alice") {
				code = errorcode.KDC_ERR_PREAUTH_REQUIRED
			}
			response := messages.NewKRBError(
				types.NewPrincipalName(2, "krbtgt/EXAMPLE.TEST"), "EXAMPLE.TEST", code, "",
			)
			payload, err := response.Marshal()
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := listener.WriteTo(payload, addr); err != nil {
				t.Error(err)
				return
			}
		}
	}()

	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	output := filepath.Join(dir, "users.txt")
	if err := ioutil.WriteFile(input, []byte("Alice\nALICE\nunknown\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupEnumTest(t, output)
	domainController = listener.LocalAddr().String()
	setupSession(userEnumCommand, nil)
	if err := userEnum(userEnumCommand, []string{input}); err != nil {
		t.Fatal(err)
	}
	got, err := ioutil.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "alice\n" {
		t.Fatalf("unexpected username output: %q", got)
	}
}

func TestUserEnumRejectsInputAsOutput(t *testing.T) {
	input := filepath.Join(t.TempDir(), "input.txt")
	if err := ioutil.WriteFile(input, []byte("alice\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupEnumTest(t, input)
	err := runUserEnum([]string{input}, func(string) (bool, error) {
		t.Fatal("input should not be tested")
		return false, nil
	})
	if err == nil || !strings.Contains(err.Error(), "must not overwrite") {
		t.Fatalf("expected input/output conflict, got %v", err)
	}
	got, err := ioutil.ReadFile(input)
	if err != nil || string(got) != "alice\n" {
		t.Fatalf("input changed: %q, %v", got, err)
	}
}

func TestUserEnumRejectsInputAsPartialOutput(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "users.txt")
	input := output + ".partial"
	if err := os.WriteFile(input, []byte("alice\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupEnumTest(t, output)
	err := runUserEnum([]string{input}, func(string) (bool, error) {
		t.Fatal("input should not be tested")
		return false, nil
	})
	if err == nil || !strings.Contains(err.Error(), "must not overwrite") {
		t.Fatalf("expected input/output conflict, got %v", err)
	}
}

func TestUserEnumSavesPartialAfterOutputFailure(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	output := filepath.Join(dir, "users.txt")
	if err := os.WriteFile(input, []byte("alice\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupEnumTest(t, output)
	err := runUserEnum([]string{input}, func(string) (bool, error) {
		if err := os.Mkdir(output, 0700); err != nil {
			t.Error(err)
		}
		return true, nil
	})
	if err == nil || !strings.Contains(err.Error(), "write username list") {
		t.Fatalf("expected output error, got %v", err)
	}
	got, err := os.ReadFile(output + ".partial")
	if err != nil || string(got) != "alice\n" {
		t.Fatalf("partial results: %q, %v", got, err)
	}
}

func TestUserEnumReportsOutputAndInputErrors(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	if err := ioutil.WriteFile(input, []byte("alice\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupEnumTest(t, filepath.Join(dir, "missing", "users.txt"))
	err := runUserEnum([]string{input}, func(string) (bool, error) { return true, nil })
	if err == nil || !strings.Contains(err.Error(), "write username list") {
		t.Fatalf("expected output error, got %v", err)
	}

	setupEnumTest(t, filepath.Join(dir, "users.txt"))
	if err := ioutil.WriteFile(input, []byte(strings.Repeat("a", 70*1024)), 0600); err != nil {
		t.Fatal(err)
	}
	err = runUserEnum([]string{input}, func(string) (bool, error) { return true, nil })
	if err == nil || !strings.Contains(err.Error(), "read username list") {
		t.Fatalf("expected input error, got %v", err)
	}
	if _, err := os.Stat(logFileName); !os.IsNotExist(err) {
		t.Fatalf("output should not exist after read error: %v", err)
	}
	if _, err := os.Stat(logFileName + ".partial"); err != nil {
		t.Fatalf("expected partial output after read error: %v", err)
	}
}

func TestUserEnumPreservesPartialResults(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	output := filepath.Join(dir, "users.txt")
	if err := os.WriteFile(input, []byte("alice\nbob\ncharlie\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(output, []byte("previous\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupEnumTest(t, output)
	threads = 1
	err := runUserEnum([]string{input}, func(username string) (bool, error) {
		if username == "alice" {
			return true, nil
		}
		return false, errors.New("fatal KDC error")
	})
	if err == nil {
		t.Fatal("expected an incomplete enumeration error")
	}
	got, err := os.ReadFile(output + ".partial")
	if err != nil || string(got) != "alice\n" {
		t.Fatalf("partial results: %q, %v", got, err)
	}
	got, err = os.ReadFile(output)
	if err != nil || string(got) != "previous\n" {
		t.Fatalf("existing output changed: %q, %v", got, err)
	}
}

func TestUserEnumInterruptSavesCompletedResult(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	output := filepath.Join(dir, "users.txt")
	if err := os.WriteFile(input, []byte("alice\nbob\n"), 0600); err != nil {
		t.Fatal(err)
	}
	setupEnumTest(t, output)
	threads = 1
	calls := 0
	err := runUserEnum([]string{input}, func(username string) (bool, error) {
		calls++
		cancel()
		return true, nil
	})
	if err == nil || calls != 1 {
		t.Fatalf("error %v, probe calls %d; want incomplete run with one probe", err, calls)
	}
	got, err := os.ReadFile(output + ".partial")
	if err != nil || string(got) != "alice\n" {
		t.Fatalf("partial results: %q, %v", got, err)
	}
}

func TestUserEnumSignalPreservesResults(t *testing.T) {
	if os.Getenv("KERBRUTE_SIGNAL_HELPER") == "1" {
		input := os.Getenv("KERBRUTE_SIGNAL_INPUT")
		output := os.Getenv("KERBRUTE_SIGNAL_OUTPUT")
		ready := os.Getenv("KERBRUTE_SIGNAL_READY")
		setupEnumTest(t, output)
		threads = 1
		domainController = "127.0.0.1:88"
		setupSession(userEnumCommand, nil)
		err := runUserEnum([]string{input}, func(string) (bool, error) {
			if err := os.WriteFile(ready, []byte("ready"), 0600); err != nil {
				panic(err)
			}
			time.Sleep(time.Second)
			return true, nil
		})
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if runtime.GOOS == "windows" {
		t.Skip("sending os.Interrupt to another process is not supported on Windows")
	}
	dir := t.TempDir()
	input := filepath.Join(dir, "input.txt")
	output := filepath.Join(dir, "users.txt")
	ready := filepath.Join(dir, "ready")
	if err := os.WriteFile(input, []byte("alice\n"), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestUserEnumSignalPreservesResults$")
	child.Env = append(os.Environ(),
		"KERBRUTE_SIGNAL_HELPER=1", "KERBRUTE_SIGNAL_INPUT="+input,
		"KERBRUTE_SIGNAL_OUTPUT="+output, "KERBRUTE_SIGNAL_READY="+ready)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not start a probe")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := child.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("interrupted run returned success")
	}
	got, err := os.ReadFile(output + ".partial")
	if err != nil || string(got) != "alice\n" {
		t.Fatalf("partial results: %q, %v", got, err)
	}
}

func TestEnumSeenSurvivesBatchAndCleansUp(t *testing.T) {
	seen, err := newEnumSeen()
	if err != nil {
		t.Fatal(err)
	}
	dir := seen.dir
	for i := 0; i < 5001; i++ {
		added, err := seen.add(fmt.Sprintf("user%05d", i))
		if err != nil || !added {
			t.Fatalf("add username %d: added %v, error %v", i, added, err)
		}
	}
	added, err := seen.add("USER00000")
	if err != nil || added {
		t.Fatalf("duplicate after batch: added %v, error %v", added, err)
	}
	if err := seen.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("temporary store was not removed: %v", err)
	}
}

func BenchmarkEnumSeen(b *testing.B) {
	seen, err := newEnumSeen()
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := seen.close(); err != nil {
			b.Error(err)
		}
	}()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := seen.add(fmt.Sprintf("user%010d", i)); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCancelledOutputLeavesExistingFileUntouched(t *testing.T) {
	output := filepath.Join(t.TempDir(), "users.txt")
	if err := os.WriteFile(output, []byte("previous\n"), 0600); err != nil {
		t.Fatal(err)
	}
	results := &enumResults{users: map[string]struct{}{"alice": {}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := results.writeFile(ctx, output); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation error, got %v", err)
	}
	got, err := os.ReadFile(output)
	if err != nil || string(got) != "previous\n" {
		t.Fatalf("existing output changed: %q, %v", got, err)
	}
}
