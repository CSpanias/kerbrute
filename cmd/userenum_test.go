package cmd

import (
	"context"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

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
	if got := atomic.LoadInt32(&counter); got != 6 {
		t.Fatalf("tested %d usernames, want 6", got)
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
}
