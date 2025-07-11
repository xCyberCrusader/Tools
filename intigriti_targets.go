package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	jsonURL                  = "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/refs/heads/main/data/intigriti_data.json"
	vdpURLsFile              = "vdp_urls.txt"
	vdpDomainsFile           = "vdp_domains.txt"
	vdpURLsOthersFile        = "vdp_urls_others.txt"
	vdpWildcardsFile         = "vdp_wildcards.txt"
	vdpWildcardsDomainsFile  = "vdp_wildcards_domains.txt"
	vdpWildcardsOthersFile   = "vdp_wildcards_others.txt"
	bbURLsFile               = "bb_urls.txt"
	bbDomainsFile            = "bb_domains.txt"
	bbURLsOthersFile         = "bb_urls_others.txt"
	bbWildcardsFile          = "bb_wildcards.txt"
	bbWildcardsDomainsFile   = "bb_wildcards_domains.txt"
	bbWildcardsOthersFile    = "bb_wildcards_others.txt"
	defaultPerm              = 0644
	maxRetries               = 3
	initialRetryWait         = 1 * time.Second
)

// Program represents the structure of an Intigriti program
type Program struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	MinBounty   Bounty `json:"min_bounty"`
	MaxBounty   Bounty `json:"max_bounty"`
	Targets     Scope  `json:"targets"`
	CompanyName string `json:"company_handle"`
}

// Bounty represents the bounty information
type Bounty struct {
	Value    float64 `json:"value"`
	Currency string  `json:"currency"`
}

// Scope contains in-scope and out-of-scope targets
type Scope struct {
	InScope  []Target `json:"in_scope"`
	OutScope []Target `json:"out_of_scope"`
}

// Target represents a single target entry
type Target struct {
	Type        string  `json:"type"`
	Endpoint    string  `json:"endpoint"`
	Description *string `json:"description"`
	Impact      *string `json:"impact"`
}

// Config holds the application configuration
type Config struct {
	ForceFetch bool
	Verbose    bool
}

// TargetGroups holds separated URLs and wildcards
type TargetGroups struct {
	URLs      []string
	Wildcards []string
}

func main() {
	cfg := parseFlags()
	setupLogging(cfg.Verbose)

	log.Println("Starting Intigriti targets extraction")

	jsonData, err := fetchJSONData(cfg)
	if err != nil {
		log.Fatalf("Failed to fetch JSON data: %v", err)
	}

	programs, err := parseJSONData(jsonData)
	if err != nil {
		log.Fatalf("Failed to parse JSON data: %v", err)
	}

	vdpTargets, bbTargets := filterAndSeparateTargets(programs)

	if err := writeOutputFiles(vdpTargets, bbTargets); err != nil {
		log.Fatalf("Failed to write output files: %v", err)
	}

	log.Println("Processing completed successfully")
}

func parseFlags() Config {
	var cfg Config
	flag.BoolVar(&cfg.ForceFetch, "fetch", false, "Force fetching the JSON even if a local copy exists")
	flag.BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose logging")
	flag.Parse()
	return cfg
}

func setupLogging(verbose bool) {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	if !verbose {
		log.SetOutput(io.Discard)
	}
}

func fetchJSONData(cfg Config) ([]byte, error) {
	var body []byte
	var err error

	for i := 0; i < maxRetries; i++ {
		body, err = attemptFetch(cfg)
		if err == nil {
			break
		}

		if i < maxRetries-1 {
			waitTime := initialRetryWait * time.Duration(1<<i)
			log.Printf("Attempt %d failed, retrying in %v: %v", i+1, waitTime, err)
			time.Sleep(waitTime)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("after %d retries: %w", maxRetries, err)
	}

	if !json.Valid(body) {
		return nil, fmt.Errorf("downloaded data is not valid JSON")
	}

	return body, nil
}

func attemptFetch(cfg Config) ([]byte, error) {
	log.Println("Fetching JSON data from", jsonURL)

	resp, err := http.Get(jsonURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	return body, nil
}

func parseJSONData(jsonData []byte) ([]Program, error) {
	var programs []Program
	if err := json.Unmarshal(jsonData, &programs); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %w", err)
	}

	if len(programs) == 0 {
		return nil, fmt.Errorf("no programs found in JSON data")
	}

	log.Printf("Successfully parsed %d programs", len(programs))
	return programs, nil
}

func filterAndSeparateTargets(programs []Program) (vdpTargets, bbTargets TargetGroups) {
	for _, program := range programs {
		if isVDPProgram(program) {
			urls, wildcards := extractAndSeparateTargets(program.Targets.InScope)
			vdpTargets.URLs = append(vdpTargets.URLs, urls...)
			vdpTargets.Wildcards = append(vdpTargets.Wildcards, wildcards...)
			log.Printf("Added %d URLs and %d wildcards from VDP program: %s", 
				len(urls), len(wildcards), program.Name)
		} else if isBugBountyProgram(program) {
			urls, wildcards := extractAndSeparateTargets(program.Targets.InScope)
			bbTargets.URLs = append(bbTargets.URLs, urls...)
			bbTargets.Wildcards = append(bbTargets.Wildcards, wildcards...)
			log.Printf("Added %d URLs and %d wildcards from bug bounty program: %s", 
				len(urls), len(wildcards), program.Name)
		}
	}

	// Normalize and deduplicate
	vdpTargets.URLs = normalizeAndDeduplicate(vdpTargets.URLs)
	vdpTargets.Wildcards = normalizeAndDeduplicate(vdpTargets.Wildcards)
	bbTargets.URLs = normalizeAndDeduplicate(bbTargets.URLs)
	bbTargets.Wildcards = normalizeAndDeduplicate(bbTargets.Wildcards)

	log.Printf("Found %d unique VDP URLs and %d unique VDP wildcards", 
		len(vdpTargets.URLs), len(vdpTargets.Wildcards))
	log.Printf("Found %d unique bug bounty URLs and %d unique bug bounty wildcards", 
		len(bbTargets.URLs), len(bbTargets.Wildcards))

	return vdpTargets, bbTargets
}

func isVDPProgram(program Program) bool {
	return program.MinBounty.Value == 0 && program.MaxBounty.Value == 0
}

func isBugBountyProgram(program Program) bool {
	return program.MaxBounty.Value > 0
}

func extractAndSeparateTargets(targets []Target) (urls, wildcards []string) {
	for _, target := range targets {
		if target.Endpoint == "" {
			continue
		}

		switch target.Type {
		case "url":
			urls = append(urls, target.Endpoint)
		case "wildcard":
			wildcards = append(wildcards, target.Endpoint)
		}
	}
	return urls, wildcards
}

func normalizeAndDeduplicate(targets []string) []string {
	unique := make(map[string]struct{})
	var result []string

	for _, target := range targets {
		normalized := strings.TrimSpace(target)
		if normalized == "" {
			continue
		}

		if _, exists := unique[normalized]; !exists {
			unique[normalized] = struct{}{}
			result = append(result, normalized)
		}
	}

	return result
}

func writeOutputFiles(vdpTargets, bbTargets TargetGroups) error {
	// Process VDP URLs
	if err := processURLs(vdpTargets.URLs, vdpURLsFile, vdpDomainsFile, vdpURLsOthersFile); err != nil {
		return fmt.Errorf("failed to process VDP URLs: %w", err)
	}

	// Process VDP Wildcards
	if err := processWildcards(vdpTargets.Wildcards, vdpWildcardsFile, vdpWildcardsDomainsFile, vdpWildcardsOthersFile); err != nil {
		return fmt.Errorf("failed to process VDP wildcards: %w", err)
	}

	// Process Bug Bounty URLs
	if err := processURLs(bbTargets.URLs, bbURLsFile, bbDomainsFile, bbURLsOthersFile); err != nil {
		return fmt.Errorf("failed to process bug bounty URLs: %w", err)
	}

	// Process Bug Bounty Wildcards
	if err := processWildcards(bbTargets.Wildcards, bbWildcardsFile, bbWildcardsDomainsFile, bbWildcardsOthersFile); err != nil {
		return fmt.Errorf("failed to process bug bounty wildcards: %w", err)
	}

	return nil
}

func processURLs(urls []string, allFile, domainsFile, othersFile string) error {
	var domains []string
	var others []string

	for _, u := range urls {
		if isDomainOnly(u) {
			domains = append(domains, u)
		} else {
			others = append(others, u)
		}
	}

	// Write all URLs
	if err := writeFile(allFile, urls); err != nil {
		return err
	}

	// Write domains only
	if err := writeFile(domainsFile, domains); err != nil {
		return err
	}

	// Write others
	if err := writeFile(othersFile, others); err != nil {
		return err
	}

	return nil
}

func processWildcards(wildcards []string, allFile, domainsFile, othersFile string) error {
	var domainWildcards []string
	var otherWildcards []string

	for _, w := range wildcards {
		if strings.HasPrefix(w, "*.") {
			// Remove the *. prefix
			domain := strings.TrimPrefix(w, "*.")
			domainWildcards = append(domainWildcards, domain)
		} else {
			otherWildcards = append(otherWildcards, w)
		}
	}

	// Write all wildcards
	if err := writeFile(allFile, wildcards); err != nil {
		return err
	}

	// Write domain wildcards only
	if err := writeFile(domainsFile, domainWildcards); err != nil {
		return err
	}

	// Write others
	if err := writeFile(othersFile, otherWildcards); err != nil {
		return err
	}

	return nil
}

func isDomainOnly(s string) bool {
	// Check if it's a valid domain (no path, query parameters, etc.)
	if !strings.Contains(s, "/") && !strings.Contains(s, "?") && !strings.Contains(s, "#") {
		// Try to parse as URL to validate
		if u, err := url.Parse("https://" + s); err == nil {
			return u.Host == s
		}
	}
	return false
}

func writeFile(filename string, lines []string) error {
	if len(lines) == 0 {
		log.Printf("No content to write for %s - skipping", filename)
		return nil
	}

	content := strings.Join(lines, "\n") + "\n"
	newChecksum := sha256.Sum256([]byte(content))

	if fileExists(filename) {
		existingContent, err := os.ReadFile(filename)
		if err != nil {
			return fmt.Errorf("failed to read existing file: %w", err)
		}

		existingChecksum := sha256.Sum256(existingContent)
		if bytes.Equal(newChecksum[:], existingChecksum[:]) {
			log.Printf("%s unchanged - skipping write", filename)
			return nil
		}
	}

	tempFile := filename + ".tmp"
	if err := os.WriteFile(tempFile, []byte(content), defaultPerm); err != nil {
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := os.Rename(tempFile, filename); err != nil {
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	log.Printf("Successfully wrote %d entries to %s", len(lines), filename)
	return nil
}

func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}