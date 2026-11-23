// Modified by CSpanias on 2026-11-23.
package cmd

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/ropnop/kerbrute/session"
	"github.com/ropnop/kerbrute/util"
	"github.com/spf13/cobra"
)

var (
	domain           string
	domainController string
	logFileName      string
	verbose          bool
	safe             bool
	delay            int
	threads          int
	stopOnSuccess    bool
	userAsPass       = false

	downgrade    bool
	hashFileName string

	logger   util.Logger
	kSession session.KerbruteSession

	// Used for multithreading
	ctx, cancel = context.WithCancel(context.Background())
	counter     int32
	successes   int32
	failureMu   sync.Mutex
	runFailure  error
)

func failRun(cancel context.CancelFunc, err error) {
	failureMu.Lock()
	if runFailure == nil {
		runFailure = err
	}
	failureMu.Unlock()
	cancel()
}

func currentFailure() error {
	failureMu.Lock()
	defer failureMu.Unlock()
	return runFailure
}

func configureThreads(requested, delayMillis int) (int, error) {
	if requested < 1 {
		return 0, fmt.Errorf("threads must be at least one")
	}
	if delayMillis < 0 {
		return 0, fmt.Errorf("delay must not be negative")
	}
	if int64(delayMillis) > math.MaxInt64/int64(time.Millisecond) {
		return 0, fmt.Errorf("delay is too large")
	}
	if delayMillis > 0 {
		return 1, nil
	}
	return requested, nil
}

func waitForDelay(ctx context.Context, delayMillis int) bool {
	if delayMillis == 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(time.Duration(delayMillis) * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return ctx.Err() == nil
	}
}

func setupSession(cmd *cobra.Command, args []string) {
	configuredThreads, err := configureThreads(threads, delay)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	threads = configuredThreads
	failureMu.Lock()
	runFailure = nil
	failureMu.Unlock()
	logPath := logFileName
	if cmd.Name() == "userenum" {
		logPath = ""
	}
	logger = util.NewLogger(verbose, logPath)
	kOptions := session.KerbruteSessionOptions{
		Domain:           domain,
		DomainController: domainController,
		Verbose:          verbose,
		SafeMode:         safe,
		HashFilename:     hashFileName,
		Downgrade:        downgrade,
	}
	k, err := session.NewKerbruteSession(kOptions)
	if err != nil {
		logger.Log.Error(err)
		os.Exit(1)
	}
	kSession = k

	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	go func(ctx context.Context, cancel context.CancelFunc, logger util.Logger) {
		defer signal.Stop(interrupts)
		select {
		case <-interrupts:
			failRun(cancel, fmt.Errorf("interrupted"))
			logger.Log.Warning("Interrupted; stopping new requests.")
		case <-ctx.Done():
		}
	}(ctx, cancel, logger)

	logger.Log.Info("Using KDC(s):")
	for _, v := range kSession.Kdcs {
		logger.Log.Infof("\t%s\n", v)
	}
	if delay != 0 {
		logger.Log.Infof("Delay set. Using single thread and delaying %dms between attempts\n", delay)
	}
}
