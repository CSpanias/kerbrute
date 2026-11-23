package cmd

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConfigureThreads(t *testing.T) {
	for _, tc := range []struct {
		threads, delay, want int
		bad                  bool
	}{
		{10, 0, 10, false},
		{10, 5, 1, false},
		{0, 0, 0, true},
		{1, -1, 0, true},
	} {
		got, err := configureThreads(tc.threads, tc.delay)
		if got != tc.want || (err != nil) != tc.bad {
			t.Errorf("configureThreads(%d, %d) = %d, %v", tc.threads, tc.delay, got, err)
		}
	}
	if strconv.IntSize == 64 {
		tooLarge := int64(math.MaxInt64)/int64(time.Millisecond) + 1
		if _, err := configureThreads(1, int(tooLarge)); err == nil {
			t.Fatal("expected an error for a delay that overflows time.Duration")
		}
	}
}

func TestPasswordWorkersStopAfterCancellation(t *testing.T) {
	delay = 0
	for _, worker := range []struct {
		name string
		run  func(context.Context, *sync.WaitGroup, func(context.Context, string, string))
	}{
		{"spray", func(ctx context.Context, wg *sync.WaitGroup, login func(context.Context, string, string)) {
			input := make(chan string, 2)
			input <- "alice"
			input <- "bob"
			close(input)
			makeSprayWorker(ctx, input, wg, "password", false, login)
		}},
		{"bruteuser", func(ctx context.Context, wg *sync.WaitGroup, login func(context.Context, string, string)) {
			input := make(chan string, 2)
			input <- "first"
			input <- "second"
			close(input)
			makeBruteWorker(ctx, input, wg, "alice", login)
		}},
		{"combos", func(ctx context.Context, wg *sync.WaitGroup, login func(context.Context, string, string)) {
			input := make(chan [2]string, 2)
			input <- [2]string{"alice", "first"}
			input <- [2]string{"bob", "second"}
			close(input)
			makeBruteComboWorker(ctx, input, wg, login)
		}},
	} {
		t.Run(worker.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var wg sync.WaitGroup
			wg.Add(1)
			calls := 0
			worker.run(ctx, &wg, func(context.Context, string, string) {
				calls++
				cancel()
			})
			wg.Wait()
			if calls != 1 {
				t.Fatalf("got %d attempts after cancellation, want one", calls)
			}
		})
	}
}

func TestDelayIsCancellable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForDelay(ctx, 60000) {
		t.Fatal("delay continued after cancellation")
	}
}

func TestEnumerationInterruptsBlockedStdin(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	originalStdin := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = originalStdin }()
	output := filepath.Join(t.TempDir(), "users.txt")
	setupEnumTest(t, output)
	done := make(chan error, 1)
	probed := make(chan struct{})
	if _, err := writer.WriteString("alice\n"); err != nil {
		t.Fatal(err)
	}
	go func() {
		done <- runUserEnum([]string{"-"}, func(username string) (bool, error) {
			close(probed)
			return true, nil
		})
	}()
	select {
	case <-probed:
	case <-time.After(2 * time.Second):
		t.Fatal("first input was not processed")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected incomplete enumeration")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("enumeration did not stop while stdin was blocked")
	}
	if got, err := os.ReadFile(output + ".partial"); err != nil || string(got) != "alice\n" {
		t.Fatalf("partial results: %q, %v", got, err)
	}
}

func TestDelaySeparatesActualAttempts(t *testing.T) {
	delay = 25
	defer func() { delay = 0 }()
	ctx := context.Background()
	input := make(chan string, 2)
	input <- "alice"
	input <- "bob"
	close(input)
	var wg sync.WaitGroup
	wg.Add(1)
	var attempts []time.Time
	makeSprayWorker(ctx, input, &wg, "password", false, func(context.Context, string, string) {
		attempts = append(attempts, time.Now())
	})
	wg.Wait()
	if len(attempts) != 2 || attempts[1].Sub(attempts[0]) < 25*time.Millisecond {
		t.Fatalf("attempts were not separated by the configured delay: %v", attempts)
	}
}

func TestEnumProgressCountsCompletedAndSkippedLines(t *testing.T) {
	line := enumProgressLine(10, 4, 2, 1, 5*time.Second)
	if !strings.Contains(line, "50.0% input lines (5/10), 4 tested, 2 valid") || !strings.Contains(line, "ETA 5s") {
		t.Fatalf("unexpected progress: %s", line)
	}
	line = enumProgressLine(-1, 4, 2, 1, 5*time.Second)
	if strings.Contains(line, "%") || !strings.Contains(line, "4 tested, 2 valid") {
		t.Fatalf("unexpected unknown-total progress: %s", line)
	}
}

func TestCountInputLinesRewindsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.txt")
	if err := os.WriteFile(path, []byte("alice\r\n\nbob"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	count, err := countInputLines(context.Background(), file)
	if err != nil || count != 3 {
		t.Fatalf("count = %d, error = %v; want three lines", count, err)
	}
	buffer := make([]byte, 5)
	if _, err := file.Read(buffer); err != nil || string(buffer) != "alice" {
		t.Fatalf("file was not rewound: %q, %v", buffer, err)
	}
}
