package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	colorRed    = "\033[0;31m"
	colorGreen  = "\033[0;32m"
	colorYellow = "\033[1;33m"
	colorBlue   = "\033[0;34m"
	colorReset  = "\033[0m"
)

type config struct {
	domain             string
	domainList         string
	outputDir          string
	profile            string
	nucleiSeverity     string
	diffMode           bool
	diffBase           string
	webhookURL         string
	webMode            bool
	webAddr            string
	threads            int
	rateLimit          int
	subfinderTimeout   int
	httpxTimeout       int
	katanaDepth        int
	katanaWorkers      int
	dirsearchThreads   int
	dirsearchRecursive bool
	timestamp          string
}

type httpxEntry struct {
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Tech       []string `json:"tech"`
}

type katanaResult struct {
	host  string
	count int
	err   error
}

type dirsearchResult struct {
	host  string
	count int
	err   error
}

type nucleiFinding struct {
	TemplateID string
	Name       string
	Severity   string
	MatchedAt  string
}

type diffSummary struct {
	CurrentTimestamp        string
	BaseTimestamp           string
	ReportPath              string
	NewSubdomains           int
	RemovedSubdomains       int
	NewLiveHosts            int
	RemovedLiveHosts        int
	NewURLs                 int
	RemovedURLs             int
	NewDirsearchPaths       int
	RemovedDirsearchPaths   int
	NewNuclei               int
	ResolvedNuclei          int
	NewHighCriticalFindings []nucleiFinding
	NewHighRiskPaths        []string
}

type safeBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

type scanJob struct {
	ID           string
	Status       string
	StartedAt    time.Time
	EndedAt      time.Time
	Config       config
	Log          safeBuffer
	ErrorMessage string
	MasterReport string
	ReadableHTML string
}

type webAppState struct {
	mu      sync.RWMutex
	current *scanJob
	rootDir string
}

var toolPaths = make(map[string]string)
var appState = webAppState{}
var outputMu sync.RWMutex
var outputWriter io.Writer = os.Stdout

func setOutputWriter(w io.Writer) func() {
	outputMu.Lock()
	prev := outputWriter
	outputWriter = w
	outputMu.Unlock()
	return func() {
		outputMu.Lock()
		outputWriter = prev
		outputMu.Unlock()
	}
}

func getOutputWriter() io.Writer {
	outputMu.RLock()
	defer outputMu.RUnlock()
	return outputWriter
}

func status(msg string) {
	fmt.Fprintf(getOutputWriter(), "%s[*]%s %s\n", colorBlue, colorReset, msg)
}

func success(msg string) {
	fmt.Fprintf(getOutputWriter(), "%s[+]%s %s\n", colorGreen, colorReset, msg)
}

func warn(msg string) {
	fmt.Fprintf(getOutputWriter(), "%s[!]%s %s\n", colorYellow, colorReset, msg)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(getOutputWriter(), "%s[!]%s %s\n", colorRed, colorReset, fmt.Sprintf(format, args...))
	os.Exit(1)
}

func usage() {
	fmt.Printf(`Usage: %s [OPTIONS]

Options:
    -d, --domain DOMAIN         Single domain to scan
    -l, --list FILE             File containing list of domains
    -o, --output DIR            Output directory (default: recon_results)
    -p, --profile PROFILE       Scan profile: quick|standard|deep (default: standard)
    -ns, --nuclei-severity S    Nuclei severities (comma-separated)
    --diff                      Compare current run with previous run
    --diff-base TS              Use specific baseline timestamp (YYYYMMDD_HHMMSS)
    --webhook-url URL           Send diff alerts to webhook URL
    --web                       Start web interface mode
    --web-addr ADDR             Web bind address (default: 127.0.0.1:8080)
    -t, --threads NUM           Threads for httpx (default: 50)
    -rl, --rate-limit NUM       Rate limit for httpx (default: 150)
    -kd, --katana-depth NUM     Crawl depth for katana (default: 3)
    -kw, --katana-workers NUM   Parallel katana workers (default: CPU count)
    -dt, --dirsearch-threads N  Dirsearch threads per host (default: 30)
    -dr, --dirsearch-recursive  Enable recursive dirsearch
    -h, --help                  Show this help message

Examples:
    %s -d example.com
    %s -d example.com -p quick
    %s -l domains.txt -o custom_output
    %s -d example.com -p deep -t 100 -rl 200 -kd 5 -kw 12
`, filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]), filepath.Base(os.Args[0]))
}

func parseArgs() config {
	cfg := defaultConfig()

	flag.Usage = usage
	flag.StringVar(&cfg.domain, "d", "", "")
	flag.StringVar(&cfg.domain, "domain", "", "")
	flag.StringVar(&cfg.domainList, "l", "", "")
	flag.StringVar(&cfg.domainList, "list", "", "")
	flag.StringVar(&cfg.outputDir, "o", cfg.outputDir, "")
	flag.StringVar(&cfg.outputDir, "output", cfg.outputDir, "")
	flag.StringVar(&cfg.profile, "p", cfg.profile, "")
	flag.StringVar(&cfg.profile, "profile", cfg.profile, "")
	flag.StringVar(&cfg.nucleiSeverity, "ns", cfg.nucleiSeverity, "")
	flag.StringVar(&cfg.nucleiSeverity, "nuclei-severity", cfg.nucleiSeverity, "")
	flag.BoolVar(&cfg.diffMode, "diff", cfg.diffMode, "")
	flag.StringVar(&cfg.diffBase, "diff-base", cfg.diffBase, "")
	flag.StringVar(&cfg.webhookURL, "webhook-url", cfg.webhookURL, "")
	flag.BoolVar(&cfg.webMode, "web", cfg.webMode, "")
	flag.StringVar(&cfg.webAddr, "web-addr", cfg.webAddr, "")
	flag.IntVar(&cfg.threads, "t", cfg.threads, "")
	flag.IntVar(&cfg.threads, "threads", cfg.threads, "")
	flag.IntVar(&cfg.rateLimit, "rl", cfg.rateLimit, "")
	flag.IntVar(&cfg.rateLimit, "rate-limit", cfg.rateLimit, "")
	flag.IntVar(&cfg.katanaDepth, "kd", cfg.katanaDepth, "")
	flag.IntVar(&cfg.katanaDepth, "katana-depth", cfg.katanaDepth, "")
	flag.IntVar(&cfg.katanaWorkers, "kw", cfg.katanaWorkers, "")
	flag.IntVar(&cfg.katanaWorkers, "katana-workers", cfg.katanaWorkers, "")
	flag.IntVar(&cfg.dirsearchThreads, "dt", cfg.dirsearchThreads, "")
	flag.IntVar(&cfg.dirsearchThreads, "dirsearch-threads", cfg.dirsearchThreads, "")
	flag.BoolVar(&cfg.dirsearchRecursive, "dr", cfg.dirsearchRecursive, "")
	flag.BoolVar(&cfg.dirsearchRecursive, "dirsearch-recursive", cfg.dirsearchRecursive, "")
	help := flag.Bool("h", false, "")
	flag.BoolVar(help, "help", false, "")
	flag.Parse()

	if *help {
		usage()
		os.Exit(0)
	}

	if err := finalizeConfig(&cfg, !cfg.webMode); err != nil {
		fatalf("%v", err)
	}
	return cfg
}

func defaultConfig() config {
	return config{
		outputDir:          "recon_results",
		profile:            "standard",
		nucleiSeverity:     "medium,high,critical",
		diffMode:           false,
		diffBase:           "",
		webhookURL:         "",
		webAddr:            "127.0.0.1:8080",
		threads:            50,
		rateLimit:          150,
		subfinderTimeout:   10,
		httpxTimeout:       10,
		katanaDepth:        3,
		katanaWorkers:      runtime.NumCPU(),
		dirsearchThreads:   30,
		dirsearchRecursive: false,
		timestamp:          time.Now().Format("20060102_150405"),
	}
}

func finalizeConfig(cfg *config, requireTarget bool) error {
	if requireTarget && cfg.domain == "" && cfg.domainList == "" {
		return errors.New("please specify either a domain (-d) or domain list (-l)")
	}
	if cfg.domain != "" && cfg.domainList != "" {
		return errors.New("please specify either a domain OR a domain list, not both")
	}
	if cfg.webMode && strings.TrimSpace(cfg.webAddr) == "" {
		return errors.New("web-addr cannot be empty in web mode")
	}

	cfg.profile = strings.ToLower(strings.TrimSpace(cfg.profile))
	switch cfg.profile {
	case "quick":
		if cfg.threads == 50 {
			cfg.threads = 25
		}
		if cfg.rateLimit == 150 {
			cfg.rateLimit = 80
		}
		if cfg.katanaDepth == 3 {
			cfg.katanaDepth = 2
		}
		if cfg.katanaWorkers == runtime.NumCPU() {
			cfg.katanaWorkers = maxInt(2, runtime.NumCPU()/2)
		}
		if cfg.dirsearchThreads == 30 {
			cfg.dirsearchThreads = 15
		}
		if cfg.nucleiSeverity == "medium,high,critical" {
			cfg.nucleiSeverity = "high,critical"
		}
	case "standard":
	case "deep":
		if cfg.threads == 50 {
			cfg.threads = 100
		}
		if cfg.rateLimit == 150 {
			cfg.rateLimit = 250
		}
		if cfg.katanaDepth == 3 {
			cfg.katanaDepth = 5
		}
		if cfg.katanaWorkers == runtime.NumCPU() {
			cfg.katanaWorkers = maxInt(runtime.NumCPU(), 4)
		}
		if cfg.dirsearchThreads == 30 {
			cfg.dirsearchThreads = 50
		}
		cfg.dirsearchRecursive = true
		if cfg.profile == "deep" && cfg.nucleiSeverity == "medium,high,critical" {
			cfg.nucleiSeverity = "low,medium,high,critical"
		}
	default:
		return fmt.Errorf("invalid profile %q (allowed: quick, standard, deep)", cfg.profile)
	}

	cfg.nucleiSeverity = strings.TrimSpace(cfg.nucleiSeverity)
	if cfg.nucleiSeverity == "" {
		return errors.New("nuclei-severity cannot be empty")
	}
	cfg.diffBase = strings.TrimSpace(cfg.diffBase)
	cfg.webhookURL = strings.TrimSpace(cfg.webhookURL)
	if cfg.diffBase != "" {
		cfg.diffMode = true
		if !regexp.MustCompile(`^\d{8}_\d{6}$`).MatchString(cfg.diffBase) {
			return errors.New("diff-base must be in format YYYYMMDD_HHMMSS")
		}
	}
	if cfg.webhookURL != "" {
		cfg.diffMode = true
	}

	if cfg.threads < 1 || cfg.rateLimit < 1 || cfg.katanaDepth < 1 || cfg.katanaWorkers < 1 || cfg.dirsearchThreads < 1 {
		return errors.New("threads, rate-limit, katana-depth, katana-workers and dirsearch-threads must all be >= 1")
	}
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}

func resolveTool(name string) (string, error) {
	candidateDirs := []string{}
	addDir := func(dir string) {
		if strings.TrimSpace(dir) != "" {
			candidateDirs = append(candidateDirs, dir)
		}
	}

	addDir(os.Getenv("GOBIN"))
	for _, gp := range filepath.SplitList(os.Getenv("GOPATH")) {
		addDir(filepath.Join(gp, "bin"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		addDir(filepath.Join(home, "go", "bin"))
	}

	seen := make(map[string]struct{}, len(candidateDirs))
	for _, dir := range candidateDirs {
		if _, ok := seen[dir]; ok {
			continue
		}
		seen[dir] = struct{}{}
		candidate := filepath.Join(dir, name)
		if isExecutable(candidate) {
			return candidate, nil
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("%s is not installed or not in PATH", name)
}

func mustTool(name string) error {
	path, err := resolveTool(name)
	if err != nil {
		return err
	}
	toolPaths[name] = path
	return nil
}

func run(name string, args ...string) error {
	cmd := commandForTool(name, args...)
	cmd.Stdout = getOutputWriter()
	cmd.Stderr = getOutputWriter()
	return cmd.Run()
}

func commandForTool(name string, args ...string) *exec.Cmd {
	cmdName := name
	if resolved, ok := toolPaths[name]; ok {
		cmdName = resolved
	} else if resolved, err := resolveTool(name); err == nil {
		cmdName = resolved
	}
	return exec.Command(cmdName, args...)
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	count := 0
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			count++
		}
	}
	return count
}

func parseStatusCode(v any) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(t))
		return n
	default:
		return 0
	}
}

func readHTTPX(jsonPath string, liveHostsPath string) ([]httpxEntry, error) {
	in, err := os.Open(jsonPath)
	if err != nil {
		return nil, err
	}
	defer in.Close()

	out, err := os.Create(liveHostsPath)
	if err != nil {
		return nil, err
	}
	defer out.Close()

	sc := bufio.NewScanner(in)
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)

	entries := make([]httpxEntry, 0, 512)
	seen := make(map[string]struct{})

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}

		u, _ := raw["url"].(string)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}

		statusCode := parseStatusCode(raw["status_code"])
		if statusCode == 0 {
			statusCode = parseStatusCode(raw["status-code"])
		}

		title, _ := raw["title"].(string)
		tech := []string{}
		if tv, ok := raw["tech"].([]any); ok {
			for _, it := range tv {
				if s, ok := it.(string); ok && s != "" {
					tech = append(tech, s)
				}
			}
		}

		entries = append(entries, httpxEntry{
			URL:        u,
			StatusCode: statusCode,
			Title:      title,
			Tech:       tech,
		})
		fmt.Fprintln(out, u)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

var badFileChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func safeHost(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Host == "" {
		return badFileChars.ReplaceAllString(strings.TrimSpace(u), "_")
	}
	host := parsed.Hostname()
	if host == "" {
		host = parsed.Host
	}
	return badFileChars.ReplaceAllString(host, "_")
}

func runKatanaParallel(urls []string, outDir string, depth, workers int) (map[string]int, []string) {
	type job struct {
		url  string
		host string
	}

	jobs := make(chan job)
	results := make(chan katanaResult, len(urls))

	workerFn := func() {
		for j := range jobs {
			outFile := filepath.Join(outDir, j.host+"_crawl.txt")
			cmd := commandForTool("katana",
				"-u", j.url,
				"-silent",
				"-depth", strconv.Itoa(depth),
				"-o", outFile,
				"-jc",
				"-ct", "60s",
				"-c", "10",
				"-rl", "50",
			)
			cmd.Stdout = getOutputWriter()
			cmd.Stderr = nil
			err := cmd.Run()
			count := countLines(outFile)
			results <- katanaResult{host: j.host, count: count, err: err}
		}
	}

	for i := 0; i < workers; i++ {
		go workerFn()
	}

	go func() {
		for _, raw := range urls {
			u := strings.TrimSpace(raw)
			if u == "" {
				continue
			}
			host := safeHost(u)
			status(fmt.Sprintf("Crawling: %s", u))
			jobs <- job{url: u, host: host}
		}
		close(jobs)
	}()

	hostCounts := make(map[string]int, len(urls))
	for i := 0; i < len(urls); i++ {
		r := <-results
		if r.err != nil {
			warn(fmt.Sprintf("Katana encountered issues with %s", r.host))
		}
		hostCounts[r.host] = r.count
		if r.count > 0 {
			success(fmt.Sprintf("Crawled %d URLs from %s", r.count, r.host))
		}
	}

	allSet := make(map[string]struct{}, 4096)
	entries, _ := os.ReadDir(outDir)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_crawl.txt") {
			continue
		}
		f, err := os.Open(filepath.Join(outDir, e.Name()))
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" {
				allSet[line] = struct{}{}
			}
		}
		f.Close()
	}

	allURLs := make([]string, 0, len(allSet))
	for u := range allSet {
		allURLs = append(allURLs, u)
	}
	sort.Strings(allURLs)
	return hostCounts, allURLs
}

func runDirsearchParallel(urls []string, outDir string, workers, dirsearchThreads int, recursive bool) (map[string]int, int) {
	type job struct {
		url  string
		host string
	}

	jobs := make(chan job)
	results := make(chan dirsearchResult, len(urls))

	workerFn := func() {
		for j := range jobs {
			outFile := filepath.Join(outDir, j.host+"_dirsearch.txt")
			args := []string{
				"-u", j.url,
				"-e", "php,asp,aspx,jsp,js,txt,zip,bak",
				"-q",
				"--no-color",
				"--full-url",
				"--format=plain",
				"-o", outFile,
				"-t", strconv.Itoa(dirsearchThreads),
			}
			if recursive {
				args = append(args, "-r")
			}
			cmd := commandForTool("dirsearch", args...)
			cmd.Stdout = nil
			cmd.Stderr = nil
			err := cmd.Run()
			count := countLines(outFile)
			results <- dirsearchResult{host: j.host, count: count, err: err}
		}
	}

	for i := 0; i < workers; i++ {
		go workerFn()
	}

	go func() {
		for _, raw := range urls {
			u := strings.TrimSpace(raw)
			if u == "" {
				continue
			}
			host := safeHost(u)
			status(fmt.Sprintf("Dirsearch: %s", u))
			jobs <- job{url: u, host: host}
		}
		close(jobs)
	}()

	hostCounts := make(map[string]int, len(urls))
	total := 0
	for i := 0; i < len(urls); i++ {
		r := <-results
		if r.err != nil {
			warn(fmt.Sprintf("Dirsearch encountered issues with %s", r.host))
		}
		hostCounts[r.host] = r.count
		total += r.count
		if r.count > 0 {
			success(fmt.Sprintf("Dirsearch found %d paths on %s", r.count, r.host))
		}
	}

	return hostCounts, total
}

func parseNucleiFindings(jsonlPath string) (map[string]int, []nucleiFinding, error) {
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
		"unknown":  0,
	}

	f, err := os.Open(jsonlPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return counts, nil, nil
		}
		return nil, nil, err
	}
	defer f.Close()

	findings := make([]nucleiFinding, 0, 64)
	sc := bufio.NewScanner(f)
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 10*1024*1024)

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var raw struct {
			TemplateID string `json:"template-id"`
			MatchedAt  string `json:"matched-at"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
		}
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			continue
		}
		sev := strings.ToLower(strings.TrimSpace(raw.Info.Severity))
		if _, ok := counts[sev]; !ok || sev == "" {
			sev = "unknown"
		}
		counts[sev]++
		findings = append(findings, nucleiFinding{
			TemplateID: raw.TemplateID,
			Name:       raw.Info.Name,
			Severity:   sev,
			MatchedAt:  raw.MatchedAt,
		})
	}

	return counts, findings, sc.Err()
}

func totalNucleiFindings(counts map[string]int) int {
	total := 0
	for _, n := range counts {
		total += n
	}
	return total
}

func runNuclei(liveHostsPath, outDir string, cfg config) (map[string]int, []nucleiFinding, error) {
	outTXT := filepath.Join(outDir, "nuclei_findings.txt")
	outJSONL := filepath.Join(outDir, "nuclei_findings.jsonl")

	err := run("nuclei",
		"-l", liveHostsPath,
		"-silent",
		"-nc",
		"-s", cfg.nucleiSeverity,
		"-o", outTXT,
		"-jle", outJSONL,
		"-rl", strconv.Itoa(cfg.rateLimit),
		"-timeout", strconv.Itoa(cfg.httpxTimeout),
	)
	if err != nil {
		return nil, nil, err
	}
	return parseNucleiFindings(outJSONL)
}

func truncate(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n])
}

func writeReadableSummary(path string, cfg config, entries []httpxEntry, hostCounts map[string]int, allURLs []string, dirsearchCounts map[string]int, nucleiCounts map[string]int, nucleiFindings []nucleiFinding, diff *diffSummary) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	defer w.Flush()

	totalNuclei := totalNucleiFindings(nucleiCounts)

	fmt.Fprintln(w, "<!doctype html>")
	fmt.Fprintln(w, "<html lang=\"en\">")
	fmt.Fprintln(w, "<head>")
	fmt.Fprintln(w, "  <meta charset=\"utf-8\">")
	fmt.Fprintln(w, "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
	fmt.Fprintln(w, "  <title>Reconnaissance Summary Report</title>")
	fmt.Fprintln(w, "  <style>")
	fmt.Fprintln(w, "    :root { color-scheme: light dark; }")
	fmt.Fprintln(w, "    * { box-sizing: border-box; }")
	fmt.Fprintln(w, "    body { margin: 0; font-family: Inter, -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Arial, sans-serif; background: linear-gradient(180deg, #0b1220 0%, #0f172a 100%); color: #e2e8f0; }")
	fmt.Fprintln(w, "    .container { max-width: 1200px; margin: 0 auto; padding: 28px 18px 36px; }")
	fmt.Fprintln(w, "    .hero { background: rgba(15,23,42,.75); border: 1px solid rgba(148,163,184,.25); border-radius: 18px; padding: 22px; backdrop-filter: blur(6px); }")
	fmt.Fprintln(w, "    .hero h1 { margin: 0 0 8px; font-size: 1.8rem; color: #f8fafc; }")
	fmt.Fprintln(w, "    .meta { display: flex; flex-wrap: wrap; gap: 10px; margin-top: 14px; }")
	fmt.Fprintln(w, "    .pill { background: rgba(30,41,59,.9); border: 1px solid rgba(148,163,184,.25); padding: 8px 10px; border-radius: 999px; color: #cbd5e1; font-size: .87rem; }")
	fmt.Fprintln(w, "    .cards { display: grid; grid-template-columns: repeat(auto-fit,minmax(170px,1fr)); gap: 12px; margin-top: 16px; }")
	fmt.Fprintln(w, "    .card { background: rgba(15,23,42,.85); border: 1px solid rgba(148,163,184,.22); border-radius: 14px; padding: 12px; }")
	fmt.Fprintln(w, "    .card .k { font-size: .78rem; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; }")
	fmt.Fprintln(w, "    .card .v { margin-top: 6px; font-size: 1.5rem; font-weight: 700; color: #f8fafc; }")
	fmt.Fprintln(w, "    section { margin-top: 16px; background: rgba(15,23,42,.85); border: 1px solid rgba(148,163,184,.2); border-radius: 14px; padding: 16px; }")
	fmt.Fprintln(w, "    h2 { margin: 0 0 12px; font-size: 1.08rem; color: #f8fafc; }")
	fmt.Fprintln(w, "    table { width: 100%; border-collapse: collapse; overflow: hidden; border-radius: 10px; }")
	fmt.Fprintln(w, "    th, td { text-align: left; padding: 10px 11px; border-bottom: 1px solid rgba(148,163,184,.18); vertical-align: top; }")
	fmt.Fprintln(w, "    th { font-size: .82rem; letter-spacing: .04em; text-transform: uppercase; color: #cbd5e1; background: rgba(30,41,59,.85); }")
	fmt.Fprintln(w, "    tr:hover td { background: rgba(30,41,59,.35); }")
	fmt.Fprintln(w, "    ul { margin: 0; padding-left: 18px; color: #dbeafe; }")
	fmt.Fprintln(w, "    li { margin: 6px 0; }")
	fmt.Fprintln(w, "    a { color: #93c5fd; text-decoration: none; word-break: break-all; }")
	fmt.Fprintln(w, "    a:hover { text-decoration: underline; }")
	fmt.Fprintln(w, "    .sev { display: inline-block; padding: 3px 9px; border-radius: 999px; font-size: .78rem; font-weight: 700; text-transform: uppercase; letter-spacing: .03em; }")
	fmt.Fprintln(w, "    .sev-critical { background: rgba(220,38,38,.2); color: #fecaca; border: 1px solid rgba(239,68,68,.45); }")
	fmt.Fprintln(w, "    .sev-high { background: rgba(249,115,22,.2); color: #fed7aa; border: 1px solid rgba(251,146,60,.45); }")
	fmt.Fprintln(w, "    .sev-medium { background: rgba(234,179,8,.2); color: #fef08a; border: 1px solid rgba(250,204,21,.45); }")
	fmt.Fprintln(w, "    .sev-low, .sev-info, .sev-unknown { background: rgba(59,130,246,.2); color: #bfdbfe; border: 1px solid rgba(96,165,250,.45); }")
	fmt.Fprintln(w, "    .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }")
	fmt.Fprintln(w, "    @media (max-width: 900px) { .grid2 { grid-template-columns: 1fr; } }")
	fmt.Fprintln(w, "  </style>")
	fmt.Fprintln(w, "</head>")
	fmt.Fprintln(w, "<body>")
	fmt.Fprintln(w, "  <div class=\"container\">")
	fmt.Fprintln(w, "    <div class=\"hero\">")
	fmt.Fprintln(w, "      <h1>Reconnaissance Summary Report</h1>")
	fmt.Fprintln(w, "      <div class=\"meta\">")
	fmt.Fprintf(w, "        <span class=\"pill\">Scan Date: %s</span>\n",
		html.EscapeString(time.Now().Format(time.RFC1123)),
	)
	fmt.Fprintf(w, "        <span class=\"pill\">Output: %s</span>\n",
		html.EscapeString(cfg.outputDir),
	)
	fmt.Fprintf(w, "        <span class=\"pill\">Profile: %s</span>\n",
		html.EscapeString(cfg.profile),
	)
	fmt.Fprintf(w, "        <span class=\"pill\">Nuclei: %s</span>\n",
		html.EscapeString(cfg.nucleiSeverity),
	)
	fmt.Fprintln(w, "      </div>")
	fmt.Fprintln(w, "      <div class=\"cards\">")
	fmt.Fprintf(w, "        <div class=\"card\"><div class=\"k\">Live Hosts</div><div class=\"v\">%d</div></div>\n", len(entries))
	fmt.Fprintf(w, "        <div class=\"card\"><div class=\"k\">Crawled URLs</div><div class=\"v\">%d</div></div>\n", len(allURLs))
	fmt.Fprintf(w, "        <div class=\"card\"><div class=\"k\">Dirsearch Paths</div><div class=\"v\">%d</div></div>\n", func() int {
		t := 0
		for _, c := range dirsearchCounts {
			t += c
		}
		return t
	}())
	fmt.Fprintf(w, "        <div class=\"card\"><div class=\"k\">Nuclei Findings</div><div class=\"v\">%d</div></div>\n", totalNuclei)
	fmt.Fprintln(w, "      </div>")
	fmt.Fprintln(w, "    </div>")
	fmt.Fprintln(w, "    <section>")
	fmt.Fprintln(w, "      <h2>Live Hosts Summary</h2>")
	fmt.Fprintln(w, "      <table>")
	fmt.Fprintln(w, "        <thead><tr><th>URL</th><th>Status</th><th>Title</th><th>Technology</th></tr></thead>")
	fmt.Fprintln(w, "        <tbody>")

	for _, e := range entries {
		statusCode := "N/A"
		if e.StatusCode > 0 {
			statusCode = strconv.Itoa(e.StatusCode)
		}
		fmt.Fprintf(w,
			"      <tr><td><a href=\"%s\" target=\"_blank\" rel=\"noopener noreferrer\">%s</a></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",
			html.EscapeString(e.URL),
			html.EscapeString(e.URL),
			html.EscapeString(statusCode),
			html.EscapeString(e.Title),
			html.EscapeString(strings.Join(e.Tech, ", ")),
		)
	}

	fmt.Fprintln(w, "        </tbody>")
	fmt.Fprintln(w, "      </table>")
	fmt.Fprintln(w, "    </section>")
	fmt.Fprintln(w, "    <div class=\"grid2\">")
	fmt.Fprintln(w, "      <section>")
	fmt.Fprintln(w, "        <h2>Crawl Statistics</h2>")
	fmt.Fprintln(w, "        <ul>")

	hosts := make([]string, 0, len(hostCounts))
	for host := range hostCounts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		fmt.Fprintf(w, "          <li><strong>%s:</strong> %d URLs discovered</li>\n", html.EscapeString(host), hostCounts[host])
	}
	fmt.Fprintln(w, "        </ul>")
	fmt.Fprintln(w, "      </section>")

	fmt.Fprintln(w, "      <section>")
	fmt.Fprintln(w, "        <h2>Sample Discovered URLs (First 20)</h2>")
	fmt.Fprintln(w, "        <ul>")
	limit := 20
	if len(allURLs) < limit {
		limit = len(allURLs)
	}
	for i := 0; i < limit; i++ {
		fmt.Fprintf(w, "          <li><a href=\"%s\" target=\"_blank\" rel=\"noopener noreferrer\">%s</a></li>\n", html.EscapeString(allURLs[i]), html.EscapeString(allURLs[i]))
	}
	if len(allURLs) > limit {
		fmt.Fprintf(w, "          <li>... and %d more URLs</li>\n", len(allURLs)-limit)
	}
	fmt.Fprintln(w, "        </ul>")
	fmt.Fprintln(w, "      </section>")
	fmt.Fprintln(w, "    </div>")
	fmt.Fprintln(w, "    <div class=\"grid2\">")
	fmt.Fprintln(w, "      <section>")
	fmt.Fprintln(w, "        <h2>Dirsearch Results by Host</h2>")
	fmt.Fprintln(w, "        <ul>")
	dsHosts := make([]string, 0, len(dirsearchCounts))
	for host := range dirsearchCounts {
		dsHosts = append(dsHosts, host)
	}
	sort.Strings(dsHosts)
	for _, host := range dsHosts {
		fmt.Fprintf(w, "          <li><strong>%s:</strong> %d paths discovered</li>\n", html.EscapeString(host), dirsearchCounts[host])
	}
	fmt.Fprintln(w, "        </ul>")
	fmt.Fprintln(w, "      </section>")
	fmt.Fprintln(w, "      <section>")
	fmt.Fprintln(w, "        <h2>Nuclei Findings</h2>")
	fmt.Fprintln(w, "        <ul>")
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		fmt.Fprintf(w, "          <li><span class=\"sev sev-%s\">%s</span> %d</li>\n", html.EscapeString(sev), html.EscapeString(strings.Title(sev)), nucleiCounts[sev])
	}
	fmt.Fprintln(w, "        </ul>")
	fmt.Fprintln(w, "      </section>")
	fmt.Fprintln(w, "    </div>")
	if len(nucleiFindings) > 0 {
		fmt.Fprintln(w, "    <section>")
		fmt.Fprintln(w, "      <h2>Sample Nuclei Findings (First 20)</h2>")
		fmt.Fprintln(w, "      <table>")
		fmt.Fprintln(w, "        <thead><tr><th>Severity</th><th>Template ID</th><th>Name</th><th>Matched At</th></tr></thead>")
		fmt.Fprintln(w, "        <tbody>")
		limit := 20
		if len(nucleiFindings) < limit {
			limit = len(nucleiFindings)
		}
		for i := 0; i < limit; i++ {
			f := nucleiFindings[i]
			fmt.Fprintf(w,
				"          <tr><td><span class=\"sev sev-%s\">%s</span></td><td>%s</td><td>%s</td><td><a href=\"%s\" target=\"_blank\" rel=\"noopener noreferrer\">%s</a></td></tr>\n",
				html.EscapeString(f.Severity),
				html.EscapeString(strings.Title(f.Severity)),
				html.EscapeString(f.TemplateID),
				html.EscapeString(f.Name),
				html.EscapeString(f.MatchedAt),
				html.EscapeString(f.MatchedAt),
			)
		}
		fmt.Fprintln(w, "        </tbody>")
		fmt.Fprintln(w, "      </table>")
		fmt.Fprintln(w, "    </section>")
	}
	if diff != nil {
		fmt.Fprintln(w, "    <section>")
		fmt.Fprintln(w, "      <h2>Differential Summary</h2>")
		fmt.Fprintln(w, "      <table>")
		fmt.Fprintln(w, "        <thead><tr><th>Metric</th><th>Added</th><th>Removed</th></tr></thead>")
		fmt.Fprintln(w, "        <tbody>")
		fmt.Fprintf(w, "          <tr><td>Subdomains</td><td>%d</td><td>%d</td></tr>\n", diff.NewSubdomains, diff.RemovedSubdomains)
		fmt.Fprintf(w, "          <tr><td>Live Hosts</td><td>%d</td><td>%d</td></tr>\n", diff.NewLiveHosts, diff.RemovedLiveHosts)
		fmt.Fprintf(w, "          <tr><td>URLs</td><td>%d</td><td>%d</td></tr>\n", diff.NewURLs, diff.RemovedURLs)
		fmt.Fprintf(w, "          <tr><td>Dirsearch Paths</td><td>%d</td><td>%d</td></tr>\n", diff.NewDirsearchPaths, diff.RemovedDirsearchPaths)
		fmt.Fprintf(w, "          <tr><td>Nuclei Findings</td><td>%d</td><td>%d</td></tr>\n", diff.NewNuclei, diff.ResolvedNuclei)
		fmt.Fprintln(w, "        </tbody>")
		fmt.Fprintln(w, "      </table>")
		fmt.Fprintf(w, "      <p>Baseline run: <strong>%s</strong> · Diff report: <code>%s</code></p>\n", html.EscapeString(diff.BaseTimestamp), html.EscapeString(diff.ReportPath))
		fmt.Fprintln(w, "    </section>")
	}
	fmt.Fprintln(w, "  </div>")
	fmt.Fprintln(w, "</body>")
	fmt.Fprintln(w, "</html>")
	return nil
}

func writeMasterReport(path string, cfg config, subfinderDir, httpxDir, katanaDir, dirsearchDir, nucleiDir string, subdomainCount, liveCount, urlCount, dirsearchCount, nucleiCount int, diff *diffSummary) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	target := cfg.domain
	if target == "" {
		target = filepath.Base(cfg.domainList)
	}

	_, err = fmt.Fprintf(f, `================================================================================
                    MASTER RECONNAISSANCE REPORT
================================================================================
Scan Date: %s
Domain(s): %s
Output Directory: %s
Profile: %s
================================================================================

FILE STRUCTURE:
--------------------------------------------------------------------------------
%s/
├── subfinder_%s/
│   └── subdomains.txt
├── httpx_%s/
│   ├── live_hosts.txt
│   └── live_hosts.json
└── katana_%s/
    ├── all_urls.txt
    ├── readable_summary.html
    └── [individual_host_crawls.txt]
└── dirsearch_%s/
    └── [individual_host_dirsearch.txt]
└── nuclei_%s/
    ├── nuclei_findings.txt
    └── nuclei_findings.jsonl

STATISTICS:
--------------------------------------------------------------------------------
  - Total subdomains discovered: %d
  - Live hosts found: %d
  - Total URLs crawled: %d
  - Total dirsearch paths found: %d
  - Total nuclei findings: %d

QUICK ACCESS:
--------------------------------------------------------------------------------
  Subdomains:      %s/subdomains.txt
  Live hosts:      %s/live_hosts.txt
  JSON results:    %s/live_hosts.json
  All URLs:        %s/all_urls.txt
  Readable report: %s/readable_summary.html
  Dirsearch files: %s/
  Nuclei findings: %s/nuclei_findings.txt
  Nuclei JSONL:    %s/nuclei_findings.jsonl
 
================================================================================
`,
		time.Now().Format(time.RFC1123),
		target,
		cfg.outputDir,
		cfg.profile,
		cfg.outputDir,
		cfg.timestamp,
		cfg.timestamp,
		cfg.timestamp,
		cfg.timestamp,
		cfg.timestamp,
		subdomainCount,
		liveCount,
		urlCount,
		dirsearchCount,
		nucleiCount,
		subfinderDir,
		httpxDir,
		httpxDir,
		katanaDir,
		katanaDir,
		dirsearchDir,
		nucleiDir,
		nucleiDir,
	)
	if err != nil {
		return err
	}
	if diff != nil {
		_, err = fmt.Fprintf(f, `
DIFF MODE:
--------------------------------------------------------------------------------
  Baseline timestamp: %s
  Diff report:        %s
  Changes:
    Subdomains       +%d  -%d
    Live hosts       +%d  -%d
    URLs             +%d  -%d
    Dirsearch paths  +%d  -%d
    Nuclei findings  +%d  -%d
  Alert candidates:
    New high/critical nuclei findings: %d
    New high-risk paths: %d
================================================================================
`,
			diff.BaseTimestamp,
			diff.ReportPath,
			diff.NewSubdomains, diff.RemovedSubdomains,
			diff.NewLiveHosts, diff.RemovedLiveHosts,
			diff.NewURLs, diff.RemovedURLs,
			diff.NewDirsearchPaths, diff.RemovedDirsearchPaths,
			diff.NewNuclei, diff.ResolvedNuclei,
			len(diff.NewHighCriticalFindings),
			len(diff.NewHighRiskPaths),
		)
	}
	return err
}

func writeAllURLs(path string, urls []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	defer w.Flush()
	for _, u := range urls {
		fmt.Fprintln(w, u)
	}
	return nil
}

func readNonEmptyLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	lines := make([]string, 0, 256)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, sc.Err()
}

func toSet(lines []string) map[string]struct{} {
	out := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		v := strings.TrimSpace(line)
		if v != "" {
			out[v] = struct{}{}
		}
	}
	return out
}

func diffSets(current, previous map[string]struct{}) (added, removed []string) {
	for item := range current {
		if _, ok := previous[item]; !ok {
			added = append(added, item)
		}
	}
	for item := range previous {
		if _, ok := current[item]; !ok {
			removed = append(removed, item)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

func listMasterTimestamps(outputDir string) ([]string, error) {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, err
	}
	const prefix = "master_report_"
	const suffix = ".txt"
	timestamps := make([]string, 0, 32)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, prefix) || !strings.HasSuffix(name, suffix) {
			continue
		}
		ts := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
		if regexp.MustCompile(`^\d{8}_\d{6}$`).MatchString(ts) {
			timestamps = append(timestamps, ts)
		}
	}
	sort.Strings(timestamps)
	return timestamps, nil
}

func previousTimestamp(outputDir, currentTimestamp, requestedBase string) (string, error) {
	if requestedBase != "" {
		return requestedBase, nil
	}
	timestamps, err := listMasterTimestamps(outputDir)
	if err != nil {
		return "", err
	}
	prev := ""
	for _, ts := range timestamps {
		if ts < currentTimestamp {
			prev = ts
		}
	}
	return prev, nil
}

func readAllDirsearchPaths(dir string) (map[string]struct{}, error) {
	out := make(map[string]struct{})
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_dirsearch.txt") {
			continue
		}
		lines, err := readNonEmptyLines(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		for _, line := range lines {
			out[line] = struct{}{}
		}
	}
	return out, nil
}

func findingKey(f nucleiFinding) string {
	return strings.ToLower(strings.TrimSpace(f.Severity)) + "|" + strings.TrimSpace(f.TemplateID) + "|" + strings.TrimSpace(f.MatchedAt)
}

func findHighRiskPaths(paths []string) []string {
	re := regexp.MustCompile(`(?i)(admin|login|config|backup|\.env|\.git|phpinfo|db|debug|dashboard|secret|token)`)
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if re.MatchString(p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func writeDiffReport(path string, d diffSummary) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, `================================================================================
                        DIFFERENTIAL RECON REPORT
================================================================================
Current Run Timestamp: %s
Baseline Timestamp:    %s
================================================================================
CHANGES:
--------------------------------------------------------------------------------
  Subdomains       +%d  -%d
  Live hosts       +%d  -%d
  URLs             +%d  -%d
  Dirsearch paths  +%d  -%d
  Nuclei findings  +%d  -%d

ALERT CANDIDATES:
--------------------------------------------------------------------------------
  New high/critical nuclei findings: %d
  New high-risk paths: %d
================================================================================
`, d.CurrentTimestamp, d.BaseTimestamp,
		d.NewSubdomains, d.RemovedSubdomains,
		d.NewLiveHosts, d.RemovedLiveHosts,
		d.NewURLs, d.RemovedURLs,
		d.NewDirsearchPaths, d.RemovedDirsearchPaths,
		d.NewNuclei, d.ResolvedNuclei,
		len(d.NewHighCriticalFindings), len(d.NewHighRiskPaths))
	return err
}

func buildDiffSummary(cfg config, subfinderOut, liveHostsPath string, allURLs []string, dirsearchDir, nucleiJSONLPath string) (*diffSummary, error) {
	baseTS, err := previousTimestamp(cfg.outputDir, cfg.timestamp, cfg.diffBase)
	if err != nil {
		return nil, err
	}
	if baseTS == "" {
		return nil, nil
	}

	currSubdomains, err := readNonEmptyLines(subfinderOut)
	if err != nil {
		return nil, err
	}
	prevSubdomains, err := readNonEmptyLines(filepath.Join(cfg.outputDir, "subfinder_"+baseTS, "subdomains.txt"))
	if err != nil {
		return nil, err
	}
	currLive, err := readNonEmptyLines(liveHostsPath)
	if err != nil {
		return nil, err
	}
	prevLive, err := readNonEmptyLines(filepath.Join(cfg.outputDir, "httpx_"+baseTS, "live_hosts.txt"))
	if err != nil {
		return nil, err
	}
	prevURLs, err := readNonEmptyLines(filepath.Join(cfg.outputDir, "katana_"+baseTS, "all_urls.txt"))
	if err != nil {
		return nil, err
	}

	currDirsearch, err := readAllDirsearchPaths(dirsearchDir)
	if err != nil {
		return nil, err
	}
	prevDirsearch, err := readAllDirsearchPaths(filepath.Join(cfg.outputDir, "dirsearch_"+baseTS))
	if err != nil {
		return nil, err
	}

	_, currNuclei, err := parseNucleiFindings(nucleiJSONLPath)
	if err != nil {
		return nil, err
	}
	_, prevNuclei, err := parseNucleiFindings(filepath.Join(cfg.outputDir, "nuclei_"+baseTS, "nuclei_findings.jsonl"))
	if err != nil {
		return nil, err
	}

	addedSubdomains, removedSubdomains := diffSets(toSet(currSubdomains), toSet(prevSubdomains))
	addedLive, removedLive := diffSets(toSet(currLive), toSet(prevLive))
	addedURLs, removedURLs := diffSets(toSet(allURLs), toSet(prevURLs))
	addedDirsearch, removedDirsearch := diffSets(currDirsearch, prevDirsearch)

	currNSet := make(map[string]nucleiFinding, len(currNuclei))
	for _, f := range currNuclei {
		currNSet[findingKey(f)] = f
	}
	prevNSet := make(map[string]nucleiFinding, len(prevNuclei))
	for _, f := range prevNuclei {
		prevNSet[findingKey(f)] = f
	}
	currNKeys := make(map[string]struct{}, len(currNSet))
	prevNKeys := make(map[string]struct{}, len(prevNSet))
	for k := range currNSet {
		currNKeys[k] = struct{}{}
	}
	for k := range prevNSet {
		prevNKeys[k] = struct{}{}
	}
	addedNucleiKeys, removedNucleiKeys := diffSets(currNKeys, prevNKeys)

	newHighCritical := make([]nucleiFinding, 0, len(addedNucleiKeys))
	for _, key := range addedNucleiKeys {
		f := currNSet[key]
		sev := strings.ToLower(strings.TrimSpace(f.Severity))
		if sev == "high" || sev == "critical" {
			newHighCritical = append(newHighCritical, f)
		}
	}

	diff := &diffSummary{
		CurrentTimestamp:        cfg.timestamp,
		BaseTimestamp:           baseTS,
		ReportPath:              filepath.Join(cfg.outputDir, "diff_report_"+cfg.timestamp+".txt"),
		NewSubdomains:           len(addedSubdomains),
		RemovedSubdomains:       len(removedSubdomains),
		NewLiveHosts:            len(addedLive),
		RemovedLiveHosts:        len(removedLive),
		NewURLs:                 len(addedURLs),
		RemovedURLs:             len(removedURLs),
		NewDirsearchPaths:       len(addedDirsearch),
		RemovedDirsearchPaths:   len(removedDirsearch),
		NewNuclei:               len(addedNucleiKeys),
		ResolvedNuclei:          len(removedNucleiKeys),
		NewHighCriticalFindings: newHighCritical,
		NewHighRiskPaths:        findHighRiskPaths(addedDirsearch),
	}
	if err := writeDiffReport(diff.ReportPath, *diff); err != nil {
		return nil, err
	}
	return diff, nil
}

func sendWebhookAlert(webhookURL string, diff *diffSummary) error {
	if webhookURL == "" || diff == nil {
		return nil
	}
	if len(diff.NewHighCriticalFindings) == 0 && len(diff.NewHighRiskPaths) == 0 {
		return nil
	}
	msg := fmt.Sprintf("webrecon diff alert (baseline %s): new high/critical nuclei=%d, new high-risk paths=%d", diff.BaseTimestamp, len(diff.NewHighCriticalFindings), len(diff.NewHighRiskPaths))
	body, err := json.Marshal(map[string]string{"text": msg})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %s", resp.Status)
	}
	return nil
}

func runPipeline(cfg config) error {
	status("Checking required tools...")
	for _, tool := range []string{"subfinder", "httpx", "katana", "dirsearch", "nuclei"} {
		if err := mustTool(tool); err != nil {
			return err
		}
	}
	success("All tools found!")
	status(fmt.Sprintf("Profile selected: %s", cfg.profile))

	if err := os.MkdirAll(cfg.outputDir, 0o755); err != nil {
		return err
	}
	success(fmt.Sprintf("Output directory created: %s", cfg.outputDir))

	subfinderDir := filepath.Join(cfg.outputDir, "subfinder_"+cfg.timestamp)
	httpxDir := filepath.Join(cfg.outputDir, "httpx_"+cfg.timestamp)
	katanaDir := filepath.Join(cfg.outputDir, "katana_"+cfg.timestamp)
	dirsearchDir := filepath.Join(cfg.outputDir, "dirsearch_"+cfg.timestamp)
	nucleiDir := filepath.Join(cfg.outputDir, "nuclei_"+cfg.timestamp)
	for _, dir := range []string{subfinderDir, httpxDir, katanaDir, dirsearchDir, nucleiDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}

	subfinderOut := filepath.Join(subfinderDir, "subdomains.txt")
	status("Running Subfinder...")
	if cfg.domain != "" {
		if err := run("subfinder", "-d", cfg.domain, "-silent", "-o", subfinderOut, "-timeout", strconv.Itoa(cfg.subfinderTimeout)); err != nil {
			return err
		}
	} else {
		if err := run("subfinder", "-dL", cfg.domainList, "-silent", "-o", subfinderOut, "-timeout", strconv.Itoa(cfg.subfinderTimeout)); err != nil {
			return err
		}
	}
	subCount := countLines(subfinderOut)
	success(fmt.Sprintf("Subfinder completed: %d subdomains found", subCount))
	if subCount == 0 {
		warn("No subdomains found. Exiting.")
		return nil
	}

	httpxJSON := filepath.Join(httpxDir, "live_hosts.json")
	liveHosts := filepath.Join(httpxDir, "live_hosts.txt")
	status("Running httpx on discovered subdomains...")
	err := run("httpx",
		"-l", subfinderOut,
		"-silent",
		"-json",
		"-o", httpxJSON,
		"-sc",
		"-title",
		"-td",
		"-server",
		"-rt",
		"-ip",
		"-cdn",
		"-threads", strconv.Itoa(cfg.threads),
		"-rate-limit", strconv.Itoa(cfg.rateLimit),
		"-timeout", strconv.Itoa(cfg.httpxTimeout),
		"-follow-redirects",
		"-max-redirects", "3",
	)
	if err != nil {
		return err
	}

	httpxEntries, err := readHTTPX(httpxJSON, liveHosts)
	if err != nil {
		return err
	}
	success(fmt.Sprintf("httpx completed: %d live hosts found", len(httpxEntries)))
	if len(httpxEntries) == 0 {
		warn("No live hosts found. Exiting.")
		return nil
	}

	status("Running Katana on live hosts (parallel)...")
	urls, err := readNonEmptyLines(liveHosts)
	if err != nil {
		return err
	}
	if len(urls) == 0 {
		return errors.New("live hosts list is empty")
	}

	hostCounts, allURLs := runKatanaParallel(urls, katanaDir, cfg.katanaDepth, cfg.katanaWorkers)
	allURLsPath := filepath.Join(katanaDir, "all_urls.txt")
	if err := writeAllURLs(allURLsPath, allURLs); err != nil {
		return err
	}
	success(fmt.Sprintf("Katana completed: %d total URLs discovered", len(allURLs)))

	status("Running Dirsearch on live hosts (parallel)...")
	dirsearchCounts, dirsearchTotal := runDirsearchParallel(urls, dirsearchDir, cfg.katanaWorkers, cfg.dirsearchThreads, cfg.dirsearchRecursive)
	success(fmt.Sprintf("Dirsearch completed: %d total paths discovered", dirsearchTotal))

	status("Running Nuclei on live hosts...")
	nucleiCounts, nucleiFindings, err := runNuclei(liveHosts, nucleiDir, cfg)
	if err != nil {
		return err
	}
	nucleiTotal := totalNucleiFindings(nucleiCounts)
	success(fmt.Sprintf("Nuclei completed: %d findings", nucleiTotal))

	var diff *diffSummary
	if cfg.diffMode {
		status("Running diff mode against baseline...")
		diff, err = buildDiffSummary(
			cfg,
			subfinderOut,
			liveHosts,
			allURLs,
			dirsearchDir,
			filepath.Join(nucleiDir, "nuclei_findings.jsonl"),
		)
		if err != nil {
			return err
		}
		if diff == nil {
			warn("No previous baseline run found for diff mode.")
		} else {
			success(fmt.Sprintf("Diff completed against baseline %s", diff.BaseTimestamp))
			success(fmt.Sprintf("Diff report generated: %s", diff.ReportPath))
		}
		if err := sendWebhookAlert(cfg.webhookURL, diff); err != nil {
			return err
		}
		if cfg.webhookURL != "" && diff != nil {
			success("Webhook alert delivered")
		}
	}

	readable := filepath.Join(katanaDir, "readable_summary.html")
	status("Generating human-readable summary...")
	if err := writeReadableSummary(readable, cfg, httpxEntries, hostCounts, allURLs, dirsearchCounts, nucleiCounts, nucleiFindings, diff); err != nil {
		return err
	}
	success(fmt.Sprintf("Readable summary generated: %s", readable))

	master := filepath.Join(cfg.outputDir, "master_report_"+cfg.timestamp+".txt")
	if err := writeMasterReport(master, cfg, subfinderDir, httpxDir, katanaDir, dirsearchDir, nucleiDir, subCount, len(httpxEntries), len(allURLs), dirsearchTotal, nucleiTotal, diff); err != nil {
		return err
	}
	success(fmt.Sprintf("Master report generated: %s", master))
	fmt.Fprintln(getOutputWriter(), "========================================================================")
	success("Reconnaissance completed successfully!")
	success(fmt.Sprintf("Results saved in: %s", cfg.outputDir))
	success(fmt.Sprintf("Master report: %s", master))
	status("Quick summary:")
	fmt.Fprintf(getOutputWriter(), "  Subdomains: %d\n", subCount)
	fmt.Fprintf(getOutputWriter(), "  Live hosts: %d\n", len(httpxEntries))
	fmt.Fprintf(getOutputWriter(), "  URLs found: %d\n", len(allURLs))
	fmt.Fprintf(getOutputWriter(), "  Dirsearch paths: %d\n", dirsearchTotal)
	fmt.Fprintf(getOutputWriter(), "  Nuclei findings: %d\n", nucleiTotal)
	if diff != nil {
		fmt.Fprintf(getOutputWriter(), "  Diff baseline: %s\n", diff.BaseTimestamp)
	}
	fmt.Fprintln(getOutputWriter(), "========================================================================")

	return nil
}

func startWebServer(addr string) error {
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	appState.mu.Lock()
	appState.rootDir = root
	appState.current = nil
	appState.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleWebHome)
	mux.HandleFunc("/start", handleWebStart)
	mux.HandleFunc("/api/state", handleWebState)
	mux.HandleFunc("/api/log", handleWebLog)
	mux.HandleFunc("/artifact", handleWebArtifact)

	status(fmt.Sprintf("Starting web interface on http://%s", addr))
	return http.ListenAndServe(addr, mux)
}

func handleWebHome(w http.ResponseWriter, r *http.Request) {
	appState.mu.RLock()
	job := appState.current
	appState.mu.RUnlock()

	statusLine := "Idle"
	if job != nil {
		statusLine = strings.ToUpper(job.Status)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>webrecon UI</title><style>
body{font-family:Arial,sans-serif;margin:24px;background:#f8fafc;color:#1f2937}
.box{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:16px;margin-bottom:16px}
label{display:block;font-weight:600;margin-top:10px} input,select{width:100%%;padding:8px;margin-top:4px;box-sizing:border-box}
button{margin-top:14px;padding:10px 14px;cursor:pointer}
pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:8px;max-height:360px;overflow:auto}
a{color:#2563eb;text-decoration:none}
</style></head><body>
<div class="box"><h2>webrecon web interface</h2><div><strong>Status:</strong> <span id="status">%s</span></div></div>
<div class="box"><h3>Start Scan</h3><form method="POST" action="/start">
<label>Domain</label><input name="domain" placeholder="example.com">
<label>Domain list file path (optional, use instead of domain)</label><input name="domain_list" placeholder="domains.txt">
<label>Output directory</label><input name="output_dir" value="recon_results">
<label>Profile</label><select name="profile"><option>quick</option><option selected>standard</option><option>deep</option></select>
<label>Nuclei severities (comma-separated)</label><input name="nuclei_severity" value="medium,high,critical">
<label>Enable diff mode</label><select name="diff_mode"><option value="false" selected>No</option><option value="true">Yes</option></select>
<label>Diff baseline timestamp (optional)</label><input name="diff_base" placeholder="20260513_010203">
<label>Webhook URL for diff alerts (optional)</label><input name="webhook_url" placeholder="https://hooks.slack.com/services/...">
<button type="submit">Run Scan</button></form></div>
<div class="box"><h3>Live Logs</h3><pre id="log">No logs yet.</pre></div>
<div class="box"><h3>Artifacts</h3><div id="artifacts">No artifacts yet.</div></div>
<script>
async function refresh(){
  try{
    const s = await fetch('/api/state').then(r=>r.json());
    document.getElementById('status').textContent = (s.status || 'idle').toUpperCase();
    const log = await fetch('/api/log').then(r=>r.text());
    document.getElementById('log').textContent = log || 'No logs yet.';
    if (s.master_report) {
      let html = '<a href="/artifact?path='+encodeURIComponent(s.master_report)+'" target="_blank">Master report</a>';
      if (s.readable_html) {
        html += ' | <a href="/artifact?path='+encodeURIComponent(s.readable_html)+'" target="_blank">Readable summary</a>';
      }
      document.getElementById('artifacts').innerHTML = html;
    }
  } catch (_) {}
}
setInterval(refresh, 2000); refresh();
</script></body></html>`, html.EscapeString(statusLine))
}

func handleWebStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	appState.mu.Lock()
	if appState.current != nil && appState.current.Status == "running" {
		appState.mu.Unlock()
		http.Error(w, "scan already running", http.StatusConflict)
		return
	}

	cfg := defaultConfig()
	cfg.timestamp = time.Now().Format("20060102_150405")
	cfg.domain = strings.TrimSpace(r.FormValue("domain"))
	cfg.domainList = strings.TrimSpace(r.FormValue("domain_list"))
	if v := strings.TrimSpace(r.FormValue("output_dir")); v != "" {
		cfg.outputDir = v
	}
	if v := strings.TrimSpace(r.FormValue("profile")); v != "" {
		cfg.profile = v
	}
	if v := strings.TrimSpace(r.FormValue("nuclei_severity")); v != "" {
		cfg.nucleiSeverity = v
	}
	cfg.diffMode = strings.EqualFold(strings.TrimSpace(r.FormValue("diff_mode")), "true")
	if v := strings.TrimSpace(r.FormValue("diff_base")); v != "" {
		cfg.diffBase = v
	}
	if v := strings.TrimSpace(r.FormValue("webhook_url")); v != "" {
		cfg.webhookURL = v
	}

	if err := finalizeConfig(&cfg, true); err != nil {
		appState.mu.Unlock()
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	job := &scanJob{
		ID:           cfg.timestamp,
		Status:       "running",
		StartedAt:    time.Now(),
		Config:       cfg,
		MasterReport: filepath.Join(cfg.outputDir, "master_report_"+cfg.timestamp+".txt"),
		ReadableHTML: filepath.Join(cfg.outputDir, "katana_"+cfg.timestamp, "readable_summary.html"),
	}
	appState.current = job
	appState.mu.Unlock()

	go runScanJob(job)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func runScanJob(job *scanJob) {
	restore := setOutputWriter(io.MultiWriter(os.Stdout, &job.Log))
	defer restore()

	status("Starting automated reconnaissance...")
	fmt.Fprintln(getOutputWriter(), "========================================================================")
	err := runPipeline(job.Config)

	appState.mu.Lock()
	defer appState.mu.Unlock()
	job.EndedAt = time.Now()
	if err != nil {
		job.Status = "failed"
		job.ErrorMessage = err.Error()
		warn(fmt.Sprintf("Scan failed: %v", err))
		return
	}
	job.Status = "done"
	success("Scan finished successfully")
}

func handleWebState(w http.ResponseWriter, r *http.Request) {
	type stateResp struct {
		Status       string `json:"status"`
		ID           string `json:"id,omitempty"`
		Error        string `json:"error,omitempty"`
		MasterReport string `json:"master_report,omitempty"`
		ReadableHTML string `json:"readable_html,omitempty"`
	}

	appState.mu.RLock()
	defer appState.mu.RUnlock()
	resp := stateResp{Status: "idle"}
	if appState.current != nil {
		resp.Status = appState.current.Status
		resp.ID = appState.current.ID
		resp.Error = appState.current.ErrorMessage
		resp.MasterReport = appState.current.MasterReport
		resp.ReadableHTML = appState.current.ReadableHTML
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func handleWebLog(w http.ResponseWriter, r *http.Request) {
	appState.mu.RLock()
	job := appState.current
	appState.mu.RUnlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if job == nil {
		_, _ = w.Write([]byte(""))
		return
	}
	_, _ = w.Write([]byte(job.Log.String()))
}

func handleWebArtifact(w http.ResponseWriter, r *http.Request) {
	rel := strings.TrimSpace(r.URL.Query().Get("path"))
	if rel == "" {
		http.Error(w, "path is required", http.StatusBadRequest)
		return
	}

	appState.mu.RLock()
	root := appState.rootDir
	appState.mu.RUnlock()

	clean := filepath.Clean(rel)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	full := filepath.Join(root, clean)
	if _, err := os.Stat(full); err != nil {
		http.Error(w, "artifact not found", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, full)
}

func main() {
	cfg := parseArgs()
	if cfg.webMode {
		if err := startWebServer(cfg.webAddr); err != nil {
			fatalf("web server failed: %v", err)
		}
		return
	}
	status("Starting automated reconnaissance...")
	fmt.Fprintln(getOutputWriter(), "========================================================================")

	if err := runPipeline(cfg); err != nil {
		fatalf("%v", err)
	}
}
