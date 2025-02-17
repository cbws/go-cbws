package v1alpha1

import (
	"context"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func newDefaultHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   2 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			IdleConnTimeout: 60 * time.Second,
		},
		Timeout: 5 * time.Second,
	}
}

var (
	onCBWSOnce sync.Once
	onCBWS     bool
)

func OnCBWS() bool {
	onCBWSOnce.Do(initOnCBWS)
	return onCBWS
}

func initOnCBWS() {
	onCBWS = testOnCBWS()
}

func testOnCBWS() bool {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resc := make(chan bool, 2)

	// Try two strategies in parallel.
	// See https://github.com/googleapis/google-cloud-go/issues/194
	go func() {
		req, _ := http.NewRequest("GET", "http://169.254.169.254/cbws/core/test", nil)
		req.Header.Set("User-Agent", "go-cbws")
		res, err := newDefaultHTTPClient().Do(req.WithContext(ctx))
		if err != nil {
			resc <- false
			return
		}
		defer res.Body.Close()
		resc <- res.StatusCode == 200
	}()

	tryHarder := systemInfoSuggestsNova()
	if tryHarder {
		res := <-resc
		if res {
			// The first strategy succeeded, so let's use it.
			return true
		}
		// Wait for either the DNS or metadata server probe to
		// contradict the other one and say we are running on
		// GCE. Give it a lot of time to do so, since the system
		// info already suggests we're running on a GCE BIOS.
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case res = <-resc:
			return res
		case <-timer.C:
			// Too slow. Who knows what this system is.
			return false
		}
	}

	return <-resc
}

func systemInfoSuggestsNova() bool {
	b, _ := os.ReadFile("/sys/class/dmi/id/product_name")
	name := strings.TrimSpace(string(b))
	return name == "OpenStack Nova"
}
