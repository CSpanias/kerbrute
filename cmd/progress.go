package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

func countInputLines(ctx context.Context, file *os.File) (int64, error) {
	buffer := make([]byte, 256*1024)
	var count int64
	var last byte
	var hasData bool
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		n, err := file.Read(buffer)
		if n > 0 {
			count += int64(bytes.Count(buffer[:n], []byte{'\n'}))
			last = buffer[n-1]
			hasData = true
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if hasData && last != '\n' {
		count++
	}
	_, err := file.Seek(0, io.SeekStart)
	return count, err
}

func enumProgressLine(total, tested, valid, skipped int64, elapsed time.Duration) string {
	seconds := elapsed.Seconds()
	if seconds <= 0 {
		seconds = 1
	}
	rate := float64(tested) / seconds
	accounted := tested + skipped
	if total < 0 || accounted > total {
		return fmt.Sprintf("Progress: %d tested, %d valid, %.1f tests/s", tested, valid, rate)
	}
	percent := 100.0
	if total > 0 {
		percent = 100 * float64(accounted) / float64(total)
	}
	filled := int(percent / 5)
	bar := strings.Repeat("#", filled) + strings.Repeat("-", 20-filled)
	eta := "unknown"
	if accounted > 0 {
		remaining := time.Duration(float64(elapsed) * float64(total-accounted) / float64(accounted))
		eta = remaining.Round(time.Second).String()
	}
	return fmt.Sprintf("Progress: [%s] %.1f%% input lines (%d/%d), %d tested, %d valid, %.1f tests/s, ETA %s",
		bar, percent, accounted, total, tested, valid, rate, eta)
}

func startEnumProgress(total int64, skipped *int64, start time.Time) func() {
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				fmt.Fprintln(os.Stderr, enumProgressLine(
					total, int64(atomic.LoadInt32(&counter)), int64(atomic.LoadInt32(&successes)),
					atomic.LoadInt64(skipped), time.Since(start)))
			case <-stop:
				return
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}
