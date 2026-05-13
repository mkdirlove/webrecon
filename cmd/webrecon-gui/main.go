package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
)

func openBrowser(target string) error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", target).Start()
	case "darwin":
		return exec.Command("open", target).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", target).Start()
	default:
		return errors.New("unsupported OS for auto-open")
	}
}

func waitForHTTP(url string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func main() {
	bin := flag.String("binary", "./webrecon", "Path to webrecon binary")
	addr := flag.String("addr", "127.0.0.1:8080", "Web UI bind address")
	noOpen := flag.Bool("no-open", false, "Do not auto-open browser")
	flag.Parse()

	webURL := "http://" + *addr
	cmd := exec.Command(*bin, "--web", "--web-addr", *addr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start webrecon web mode: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("webrecon GUI launcher started.\nWeb UI: %s\nPID: %d\n", webURL, cmd.Process.Pid)

	if !*noOpen && waitForHTTP(webURL, 10*time.Second) {
		if err := openBrowser(webURL); err != nil {
			fmt.Fprintf(os.Stderr, "failed to open browser: %v\n", err)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "webrecon exited with error: %v\n", err)
			os.Exit(1)
		}
	case <-sigCh:
		fmt.Println("\nshutting down webrecon GUI launcher...")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if cmd.Process != nil {
			_ = cmd.Process.Signal(os.Interrupt)
		}
		select {
		case <-waitCh:
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	}
}
