// Modified by CSpanias on 2026-11-23.
package cmd

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
)

func makeSprayWorker(ctx context.Context, usernames <-chan string, wg *sync.WaitGroup, password string, userAsPass bool, login func(context.Context, string, string)) {
	defer wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case username, ok := <-usernames:
			if !ok || !waitForDelay(ctx, delay) {
				return
			}
			if userAsPass {
				login(ctx, username, username)
			} else {
				login(ctx, username, password)
			}
		}
	}
}

func makeBruteWorker(ctx context.Context, passwords <-chan string, wg *sync.WaitGroup, username string, login func(context.Context, string, string)) {
	defer wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case password, ok := <-passwords:
			if !ok || !waitForDelay(ctx, delay) {
				return
			}
			login(ctx, username, password)
		}
	}
}

func makeEnumWorker(ctx context.Context, usernames <-chan string, wg *sync.WaitGroup, results *enumResults, probe func(string) (bool, error)) {
	defer wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case username, ok := <-usernames:
			if !ok || !waitForDelay(ctx, delay) {
				return
			}
			testUsername(username, results, probe)
		}
	}
}

func makeBruteComboWorker(ctx context.Context, combos <-chan [2]string, wg *sync.WaitGroup, login func(context.Context, string, string)) {
	defer wg.Done()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case combo, ok := <-combos:
			if !ok || !waitForDelay(ctx, delay) {
				return
			}
			login(ctx, combo[0], combo[1])
		}
	}
}

func testLogin(ctx context.Context, username string, password string) {
	atomic.AddInt32(&counter, 1)
	login := fmt.Sprintf("%v@%v:%v", username, domain, password)
	if ok, err := kSession.TestLogin(username, password); ok {
		atomic.AddInt32(&successes, 1)
		if err != nil { // it's a valid login, but there's an error we should display
			logger.Log.Noticef("[+] VALID LOGIN WITH ERROR:\t %s\t (%s)", login, err)
		} else {
			logger.Log.Noticef("[+] VALID LOGIN:\t %s", login)
		}
		if stopOnSuccess {
			cancel()
		}
	} else {
		// This is to determine if the error is "okay" or if we should abort everything
		ok, errorString := kSession.HandleKerbError(err)
		if !ok {
			logger.Log.Errorf("[!] %v - %v", login, errorString)
			failRun(cancel, fmt.Errorf("%s", errorString))
		} else {
			logger.Log.Debugf("[!] %v - %v", login, errorString)
		}
	}
}

func testUsername(username string, results *enumResults, probe func(string) (bool, error)) {
	defer atomic.AddInt32(&counter, 1)
	usernamefull := fmt.Sprintf("%v@%v", username, domain)
	valid, err := probe(username)
	if valid {
		if !results.add(username) {
			return
		}
		atomic.AddInt32(&successes, 1)
		if err != nil {
			logger.Log.Noticef("[+] VALID USERNAME WITH ERROR:\t %s\t (%s)", username, err)
		} else {
			logger.Log.Noticef("[+] VALID USERNAME:\t %s", usernamefull)
		}

	} else if err != nil {
		// This is to determine if the error is "okay" or if we should abort everything
		ok, errorString := kSession.HandleKerbError(err)
		if !ok {
			logger.Log.Errorf("[!] %v - %v", usernamefull, errorString)
			failRun(cancel, fmt.Errorf("%s", errorString))
		} else {
			logger.Log.Debugf("[!] %v - %v", usernamefull, errorString)
		}
	} else {
		logger.Log.Debug("[!] Unknown behavior - %v", usernamefull)
	}
}
