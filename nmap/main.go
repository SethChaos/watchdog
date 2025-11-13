package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/redis/go-redis/v9"
)

// Scan Profiles
type ScanProfile string

const (
	ScanBasic ScanProfile = "basic"
	ScanDeep  ScanProfile = "deep"
)

// Nmap XML Result Structures
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
	Stats   Stats    `xml:"runstats"`
}

type Host struct {
	Status    Status     `xml:"status"`
	Addresses []Address  `xml:"address"`
	Hostnames []Hostname `xml:"hostnames>hostname"`
	Ports     []Port     `xml:"ports>port"`
	OS        OS         `xml:"os"`
}

type Status struct {
	State string `xml:"state,attr"`
}

type Address struct {
	Addr string `xml:"addr,attr"`
	Type string `xml:"addrtype,attr"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
}

type Port struct {
	Protocol string   `xml:"protocol,attr"`
	PortID   int      `xml:"portid,attr"`
	State    State    `xml:"state"`
	Service  Service  `xml:"service"`
	Scripts  []Script `xml:"script"`
}

type State struct {
	State string `xml:"state,attr"`
}

type Service struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type Script struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type OS struct {
	OSMatches []OSMatch `xml:"osmatch"`
}

type OSMatch struct {
	Name      string    `xml:"name,attr"`
	Accuracy  int       `xml:"accuracy,attr"`
	OSClasses []OSClass `xml:"osclass"`
}

type OSClass struct {
	Vendor   string `xml:"vendor,attr"`
	OSFamily string `xml:"osfamily,attr"`
	Type     string `xml:"type,attr"`
}

type Stats struct {
	Finished Finished  `xml:"finished"`
	Hosts    HostStats `xml:"hosts"`
}

type Finished struct {
	Elapsed float64 `xml:"elapsed,attr"`
}

type HostStats struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

// Scanner Service
type NmapScanner struct {
	redisClient *redis.Client
}

func NewNmapScanner(redisAddr string) *NmapScanner {
	return &NmapScanner{
		redisClient: redis.NewClient(&redis.Options{
			Addr:     redisAddr,
			Password: "",
			DB:       0,
		}),
	}
}

// Scan Job from Queue
type ScanJob struct {
	ScanID      string      `json:"scan_id"`
	Target      string      `json:"target"`
	ScanType    ScanProfile `json:"scan_type"`
	CallbackURL string      `json:"callback_url"`
	Timeout     int         `json:"timeout"`
}

// Scan Result
type ScanResult struct {
	ScanID   string      `json:"scan_id"`
	Tool     string      `json:"tool"`
	ScanType ScanProfile `json:"scan_type"`
	Results  interface{} `json:"results"`
	ScanTime string      `json:"scan_time"`
	Error    string      `json:"error,omitempty"`
}

// Main Scanner Entry Point
func (s *NmapScanner) Start() error {
	ctx := context.Background()

	// Test Redis connection
	_, err := s.redisClient.Ping(ctx).Result()
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %v", err)
	}
	fmt.Println("✅ Unified Nmap Scanner connected to Redis successfully")

	// Start listening for all scan types
	fmt.Println("📡 Listening for scan jobs on 'nmap_scans_queue'...")

	for {
		// Wait for job with 30 second timeout
		job, err := s.redisClient.BLPop(ctx, 30*time.Second, "nmap_scans_queue").Result()
		if err != nil && err != redis.Nil {
			log.Printf("⚠️ Error reading from queue: %v", err)
			continue
		}

		if len(job) < 2 {
			// No jobs, continue waiting
			continue
		}

		var scanJob ScanJob
		err = json.Unmarshal([]byte(job[1]), &scanJob)
		if err != nil {
			log.Printf("❌ Error parsing job: %v", err)
			continue
		}

		fmt.Printf("🎯 New %s scan job: %s -> %s\n", scanJob.ScanType, scanJob.ScanID, scanJob.Target)
		go s.processScan(ctx, scanJob)
	}
}

// Process Scan with Selected Profile
func (s *NmapScanner) processScan(ctx context.Context, job ScanJob) {
	startTime := time.Now()
	result := ScanResult{
		ScanID:   job.ScanID,
		Tool:     "nmap",
		ScanType: job.ScanType,
		ScanTime: time.Since(startTime).String(),
	}

	// Set timeout (default to 5 minutes if not provided)
	timeout := 5 * time.Minute
	if job.Timeout > 0 {
		timeout = time.Duration(job.Timeout) * time.Second
	}

	fmt.Printf("⏰ Starting %s scan with timeout: %v\n", job.ScanType, timeout)

	// Create context with timeout
	scanCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Run the scan using system nmap
	nmapResult, err := s.runSystemNmap(scanCtx, job.Target, job.ScanType)
	if err != nil {
		result.Error = fmt.Sprintf("Scan failed: %v", err)
		s.sendResult(result)
		return
	}

	result.Results = s.formatScanResults(nmapResult)
	result.ScanTime = time.Since(startTime).String()

	s.sendResult(result)
	fmt.Printf("✅ %s scan completed in %s: %s\n", job.ScanType, result.ScanTime, job.ScanID)
}

// Run System Nmap with Profile Configuration
func (s *NmapScanner) runSystemNmap(ctx context.Context, target string, profile ScanProfile) (*NmapRun, error) {
	// Build nmap command based on profile
	args := []string{"-oX", "-"} // Output XML to stdout

	switch profile {
	case ScanBasic:
		// Basic: nmap -sS -sV --top-ports 1000 -T4 --open
		args = append(args,
			"-sS",                 // SYN scan
			"-sV",                 // Version detection
			"--top-ports", "1000", // Top 1000 ports
			"-T4",    // Aggressive timing
			"--open", // Only show open ports
		)
	case ScanDeep:
		// Deep: nmap -sS -sV -sC -O -p- -T3 --min-rate 500
		args = append(args,
			"-sS",               // SYN scan
			"-sV",               // Version detection
			"-sC",               // Default script scan
			"-O",                // OS detection
			"-p-",               // All ports
			"-T3",               // Normal timing
			"--min-rate", "500", // Minimum 500 packets/sec
		)
	default:
		return nil, fmt.Errorf("unknown scan profile: %s", profile)
	}

	// Add target
	args = append(args, target)

	fmt.Printf("🔍 Running: nmap %v\n", args)

	// Execute nmap
	cmd := exec.CommandContext(ctx, "nmap", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		return nil, fmt.Errorf("nmap execution failed: %v\nOutput: %s", err, string(output))
	}

	// Parse XML output
	var nmapRun NmapRun
	err = xml.Unmarshal(output, &nmapRun)
	if err != nil {
		return nil, fmt.Errorf("failed to parse nmap XML: %v\nXML: %s", err, string(output))
	}

	return &nmapRun, nil
}

// Format Results to Consistent JSON Structure
func (s *NmapScanner) formatScanResults(nmapRun *NmapRun) map[string]interface{} {
	summary := map[string]interface{}{
		"total_hosts": len(nmapRun.Hosts),
		"scan_stats": map[string]interface{}{
			"duration":    nmapRun.Stats.Finished.Elapsed,
			"hosts_up":    nmapRun.Stats.Hosts.Up,
			"hosts_down":  nmapRun.Stats.Hosts.Down,
			"hosts_total": nmapRun.Stats.Hosts.Total,
		},
	}

	hosts := []map[string]interface{}{}

	for _, host := range nmapRun.Hosts {
		hostInfo := map[string]interface{}{
			"address":  s.getHostAddress(host),
			"status":   host.Status.State,
			"hostname": s.getHostnames(host.Hostnames),
			"os_guess": s.getOSGuess(host.OS),
		}

		// Port information
		ports := []map[string]interface{}{}
		for _, port := range host.Ports {
			portInfo := map[string]interface{}{
				"port":     port.PortID,
				"protocol": port.Protocol,
				"state":    port.State.State,
				"service":  port.Service.Name,
				"version":  port.Service.Version,
				"product":  port.Service.Product,
			}
			ports = append(ports, portInfo)
		}
		hostInfo["ports"] = ports

		// Vulnerability scripts results
		scripts := []map[string]interface{}{}
		for _, port := range host.Ports {
			for _, script := range port.Scripts {
				scripts = append(scripts, map[string]interface{}{
					"port":   port.PortID,
					"script": script.ID,
					"output": script.Output,
				})
			}
		}
		hostInfo["scripts"] = scripts

		hosts = append(hosts, hostInfo)
	}

	return map[string]interface{}{
		"summary": summary,
		"hosts":   hosts,
	}
}

// Helper functions
func (s *NmapScanner) getHostAddress(host Host) string {
	if len(host.Addresses) > 0 {
		return host.Addresses[0].Addr
	}
	return "unknown"
}

func (s *NmapScanner) getHostnames(hostnames []Hostname) []string {
	names := []string{}
	for _, hn := range hostnames {
		names = append(names, hn.Name)
	}
	return names
}

func (s *NmapScanner) getOSGuess(os OS) string {
	if len(os.OSMatches) > 0 {
		bestMatch := os.OSMatches[0]
		for _, match := range os.OSMatches {
			if match.Accuracy > bestMatch.Accuracy {
				bestMatch = match
			}
		}
		if len(bestMatch.OSClasses) > 0 {
			osClass := bestMatch.OSClasses[0]
			return fmt.Sprintf("%s %s %s (%d%% confidence)",
				osClass.Vendor, osClass.OSFamily, osClass.Type, bestMatch.Accuracy)
		}
		return fmt.Sprintf("Unknown OS (%d%% confidence)", bestMatch.Accuracy)
	}
	return "unknown"
}

// Send Results to Redis
func (s *NmapScanner) sendResult(result ScanResult) {
	jsonData, err := json.Marshal(result)
	if err != nil {
		log.Printf("❌ Error marshaling result: %v", err)
		return
	}

	ctx := context.Background()
	err = s.redisClient.RPush(ctx, "scan_results", jsonData).Err()
	if err != nil {
		log.Printf("❌ Error sending result to Redis: %v", err)
		return
	}

	fmt.Printf("📤 Results sent to Redis for scan: %s\n", result.ScanID)
}

// Main function
func main() {
	fmt.Println("🚀 Starting Unified Nmap Scanner (Basic & Deep Scans Only)...")

	scanner := NewNmapScanner("localhost:6379")

	if err := scanner.Start(); err != nil {
		log.Fatal("❌ Failed to start scanner:", err)
	}
}
