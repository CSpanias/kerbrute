package cmd

import (
	"bufio"
	"context"
)

type scanResult struct {
	line string
	err  error
}

func scanLines(ctx context.Context, scanner *bufio.Scanner) <-chan scanResult {
	results := make(chan scanResult)
	go func() {
		defer close(results)
		for scanner.Scan() {
			select {
			case results <- scanResult{line: scanner.Text()}:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case results <- scanResult{err: err}:
			case <-ctx.Done():
			}
		}
	}()
	return results
}
