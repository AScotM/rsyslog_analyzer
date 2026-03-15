package main

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	RecentDaysCount     = 7
	DefaultMaxFileSize  = 100 * 1024 * 1024
	MaxDisplayErrors    = 10
	MaxDisplayFiltered  = 20
	MaxErrorPatterns    = 10
	MaxTopServices      = 5
	MaxPointerJumps     = 20
	MaxPatternTypes     = 10
	MaxMonthDetection   = 12
	MaxDecompressedSize = 100 * 1024 * 1024
	MaxLineLength       = 10 * 1024 * 1024
	CommandTimeout      = 5 * time.Second
)

var (
	defaultSyslogPaths = []string{
		"/var/log/messages",
		"/var/log/syslog",
		"/var/log/system.log",
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/kern.log",
		"/var/log/dmesg",
		"/var/log/debug",
	}

	months = map[string]time.Month{
		"Jan": time.January, "Feb": time.February, "Mar": time.March,
		"Apr": time.April,   "May": time.May,      "Jun": time.June,
		"Jul": time.July,    "Aug": time.August,   "Sep": time.September,
		"Oct": time.October, "Nov": time.November, "Dec": time.December,
	}

	allowedDirs = []string{"/var/log", "/tmp/logs", "/opt/logs", "/var/log/journal", "/run/log"}
	
	traditionalPattern = regexp.MustCompile(
		`^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+` +
			`(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+` +
			`(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)` +
			`(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$`)
	
	traditionalSimplePattern = regexp.MustCompile(
		`^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+` +
			`(?P<time>\d{2}:\d{2}:\d{2})\s+` +
			`(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s*` +
			`(?P<message>.+)$`)
	
	iso8601Pattern = regexp.MustCompile(
		`^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?(?:\s+[+-]\d{4})?)\s+` +
			`(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)(?:\[(?P<pid>\d+)\])?:\s*` +
			`(?P<message>.+)$`)
	
	journaldPattern = regexp.MustCompile(
		`^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4})\s+` +
			`(?P<host>[\w\-.]+)\s+(?P<service>\w+)\[(?P<pid>\d+)\]:\s*` +
			`(?P<message>.+)$`)
	
	rainerscriptPattern = regexp.MustCompile(
		`^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+[\d+-:]+)\s+` +
			`(?P<host>\S+)\s+` +
			`(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:?\s+` +
			`(?:\[(?P<level>\w+)\]\s+)?` +
			`(?P<message>.+)$`)
)

type SecurityError struct {
	Message string
}

func (e SecurityError) Error() string {
	return e.Message
}

type RSyslogInfo struct {
	Version          string
	Features         map[string]bool
	ConfigFile       string
	PidFile          string
	Platform         string
	RainerscriptBits int
}

func (r *RSyslogInfo) DetectRSyslogInfo() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "rsyslogd", "-v")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return r.parseVersionOutput(string(output)), nil
	}
	return r.detectFromSystem()
}

func (r *RSyslogInfo) parseVersionOutput(output string) bool {
	lines := strings.Split(output, "\n")
	if len(lines) == 0 {
		return false
	}

	versionMatch := regexp.MustCompile(`rsyslogd\s+([\d.]+)`).FindStringSubmatch(lines[0])
	if len(versionMatch) > 1 {
		r.Version = versionMatch[1]
	}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Config file:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				r.ConfigFile = strings.TrimSpace(parts[1])
			}
		} else if strings.HasPrefix(line, "PID file:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				r.PidFile = strings.TrimSpace(parts[1])
			}
		} else if strings.Contains(line, "Number of Bits in RainerScript integers:") {
			bitsMatch := regexp.MustCompile(`(\d+)`).FindStringSubmatch(line)
			if len(bitsMatch) > 1 {
				r.RainerscriptBits, _ = strconv.Atoi(bitsMatch[1])
			}
		} else if strings.Contains(line, ":") && (strings.Contains(line, "Yes") || strings.Contains(line, "No")) {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				feature := strings.TrimSpace(parts[0])
				value := strings.Contains(parts[1], "Yes")
				if r.Features == nil {
					r.Features = make(map[string]bool)
				}
				r.Features[feature] = value
			}
		}
	}

	return true
}

func (r *RSyslogInfo) detectFromSystem() (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), CommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "pgrep", "rsyslog")
	output, err := cmd.CombinedOutput()
	if err == nil && len(output) > 0 {
		r.Version = "unknown (running)"

		possibleConfigs := []string{
			"/etc/rsyslog.conf",
			"/etc/rsyslog.d/",
			"/usr/local/etc/rsyslog.conf",
		}
		for _, config := range possibleConfigs {
			if _, err := os.Stat(config); err == nil {
				r.ConfigFile = config
				break
			}
		}
		return true, nil
	}
	return false, errors.New("rsyslog not detected")
}

type PatternInfo struct {
	Pattern     *regexp.Regexp
	Type        string
	Description string
}

func (r *RSyslogInfo) GetRecommendedPatterns() []PatternInfo {
	patterns := []PatternInfo{
		{
			Pattern:     traditionalPattern,
			Type:        "traditional",
			Description: "Basic syslog format",
		},
		{
			Pattern:     traditionalSimplePattern,
			Type:        "traditional_simple",
			Description: "Simple syslog format",
		},
	}

	if r.Version != "" && r.versionCompare(r.Version, "8.0") >= 0 {
		patterns = append(patterns, PatternInfo{
			Pattern:     iso8601Pattern,
			Type:        "iso8601",
			Description: "ISO 8601 timestamp format",
		})

		patterns = append(patterns, PatternInfo{
			Pattern:     journaldPattern,
			Type:        "journald",
			Description: "Journald-style format",
		})
	}

	if r.Features["FEATURE_REGEXP"] {
		patterns = append(patterns, PatternInfo{
			Pattern:     rainerscriptPattern,
			Type:        "rainerscript_enhanced",
			Description: "RainerScript enhanced format",
		})
	}

	return patterns
}

func (r *RSyslogInfo) versionCompare(v1, v2 string) int {
	normalize := func(v string) []int {
		clean := regexp.MustCompile(`[^0-9.]`).ReplaceAllString(v, "")
		parts := strings.Split(clean, ".")
		result := make([]int, len(parts))
		for i, part := range parts {
			result[i], _ = strconv.Atoi(part)
		}
		return result
	}

	v1Norm := normalize(v1)
	v2Norm := normalize(v2)

	maxLen := len(v1Norm)
	if len(v2Norm) > maxLen {
		maxLen = len(v2Norm)
	}

	for i := 0; i < maxLen; i++ {
		v1Part := 0
		if i < len(v1Norm) {
			v1Part = v1Norm[i]
		}
		v2Part := 0
		if i < len(v2Norm) {
			v2Part = v2Norm[i]
		}
		if v1Part != v2Part {
			return v1Part - v2Part
		}
	}
	return 0
}

func (r *RSyslogInfo) GetConfigRecommendations() map[string]string {
	recommendations := make(map[string]string)

	if r.Version != "" && r.versionCompare(r.Version, "8.0") < 0 {
		recommendations["version"] = "Consider upgrading to rsyslog 8.x+ for better features"
	}

	if !r.Features["FEATURE_REGEXP"] {
		recommendations["regexp"] = "Rebuild rsyslog with regexp support for better parsing"
	}

	if r.ConfigFile != "" {
		content, err := os.ReadFile(r.ConfigFile)
		if err == nil {
			configContent := string(content)
			if !strings.Contains(configContent, "imfile") {
				recommendations["imfile"] = "Consider enabling imfile module for file monitoring"
			}
			if strings.Contains(configContent, "omelasticsearch") {
				recommendations["elastic"] = "Elasticsearch output detected - consider using elastic tools"
			}
		}
	}

	return recommendations
}

type AnalyzerConfig struct {
	MaxDays             int
	TruncateLength      int
	ShowFullLines       bool
	WrapLines           bool
	MaxLinesPerService  int
	ColorOutput         bool
	Verbose             bool
	EnableAnalysis      bool
	MaxFileSizeMB       int
	UseRSyslogDetection bool
	MaxMemoryEntries    int
}

func NewDefaultConfig() *AnalyzerConfig {
	return &AnalyzerConfig{
		MaxDays:             30,
		TruncateLength:      80,
		ShowFullLines:       false,
		WrapLines:           false,
		MaxLinesPerService:  5,
		ColorOutput:         true,
		Verbose:             false,
		EnableAnalysis:      false,
		MaxFileSizeMB:       100,
		UseRSyslogDetection: true,
		MaxMemoryEntries:    100000,
	}
}

func (c *AnalyzerConfig) Validate() error {
	if c.MaxDays <= 0 {
		return fmt.Errorf("MaxDays must be positive")
	}
	if c.MaxFileSizeMB <= 0 {
		return fmt.Errorf("MaxFileSizeMB must be positive")
	}
	if c.MaxFileSizeMB > 1024 {
		return fmt.Errorf("max file size too large")
	}
	if c.MaxMemoryEntries <= 0 {
		return fmt.Errorf("MaxMemoryEntries must be positive")
	}
	if c.MaxMemoryEntries > 1000000 {
		return fmt.Errorf("excessive memory allocation")
	}
	if c.TruncateLength <= 0 {
		return fmt.Errorf("TruncateLength must be positive")
	}
	if c.MaxLinesPerService <= 0 {
		return fmt.Errorf("MaxLinesPerService must be positive")
	}
	return nil
}

func (c *AnalyzerConfig) FromFile(configPath string) error {
	if strings.Contains(configPath, "..") || strings.ContainsAny(configPath, "/\\") {
		return SecurityError{Message: "invalid config file path"}
	}
	
	content, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}
	if err := json.Unmarshal(content, c); err != nil {
		return fmt.Errorf("failed to parse config JSON: %w", err)
	}
	return c.Validate()
}

type LogEntry struct {
	Timestamp time.Time
	Service   string
	Message   string
	Level     string
	Host      string
	PID       string
	RawLine   string
}

func (l *LogEntry) IsError() bool {
	if l.Level != "" {
		upperLevel := strings.ToUpper(l.Level)
		return upperLevel == "ERROR" || upperLevel == "CRITICAL" || upperLevel == "FATAL"
	}
	errorIndicators := []string{"error", "failed", "failure", "exception", "critical", "panic"}
	lowerMessage := strings.ToLower(l.Message)
	for _, indicator := range errorIndicators {
		if strings.Contains(lowerMessage, indicator) {
			return true
		}
	}
	return false
}

type AnalysisResults struct {
	TotalEntries       int
	UniqueServices     map[string]bool
	DateRange          [2]string
	ServiceCounts      map[string]int
	ErrorCount         int
	LevelDistribution  map[string]int
	HourlyDistribution map[string]int
	mu                 sync.Mutex
}

func NewAnalysisResults() *AnalysisResults {
	return &AnalysisResults{
		UniqueServices:     make(map[string]bool),
		ServiceCounts:      make(map[string]int),
		LevelDistribution:  make(map[string]int),
		HourlyDistribution: make(map[string]int),
	}
}

func (a *AnalysisResults) Update(entry *LogEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.TotalEntries++
	a.UniqueServices[entry.Service] = true
	a.ServiceCounts[entry.Service]++

	if entry.Level != "" {
		upperLevel := strings.ToUpper(entry.Level)
		a.LevelDistribution[upperLevel]++
	}

	if entry.IsError() {
		a.ErrorCount++
	}

	hourKey := entry.Timestamp.Format("15:00")
	a.HourlyDistribution[hourKey]++
}

type AnalysisPlugin interface {
	ProcessEntry(entry *LogEntry)
	GetResults() map[string]interface{}
}

type ErrorClusterPlugin struct {
	ErrorPatterns map[string]int
	ServiceErrors map[string]map[string]int
	mu            sync.RWMutex
}

func NewErrorClusterPlugin() *ErrorClusterPlugin {
	return &ErrorClusterPlugin{
		ErrorPatterns: make(map[string]int),
		ServiceErrors: make(map[string]map[string]int),
	}
}

func (e *ErrorClusterPlugin) ProcessEntry(entry *LogEntry) {
	if !entry.IsError() {
		return
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	pattern := e.extractErrorPattern(entry.Message)
	e.ErrorPatterns[pattern]++

	if e.ServiceErrors[entry.Service] == nil {
		e.ServiceErrors[entry.Service] = make(map[string]int)
	}
	e.ServiceErrors[entry.Service][pattern]++
}

func (e *ErrorClusterPlugin) extractErrorPattern(message string) string {
	words := strings.Fields(message)
	if len(words) > 3 {
		return strings.Join(words[:3], " ") + "..."
	}
	return message
}

func (e *ErrorClusterPlugin) GetResults() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	topPatterns := make(map[string]int)
	patterns := make([]string, 0, len(e.ErrorPatterns))
	for pattern := range e.ErrorPatterns {
		patterns = append(patterns, pattern)
	}
	sort.Slice(patterns, func(i, j int) bool {
		return e.ErrorPatterns[patterns[i]] > e.ErrorPatterns[patterns[j]]
	})
	for i, pattern := range patterns {
		if i >= MaxErrorPatterns {
			break
		}
		topPatterns[pattern] = e.ErrorPatterns[pattern]
	}

	serviceErrors := make(map[string]map[string]int)
	for service, patterns := range e.ServiceErrors {
		serviceErrors[service] = make(map[string]int)
		for pattern, count := range patterns {
			serviceErrors[service][pattern] = count
		}
	}

	return map[string]interface{}{
		"top_error_patterns": topPatterns,
		"service_errors":     serviceErrors,
	}
}

type BoundedLogStorage struct {
	entries []*LogEntry
	maxSize int
	head    int
	tail    int
	size    int
	mu      sync.RWMutex
}

func NewBoundedLogStorage(maxSize int) *BoundedLogStorage {
	return &BoundedLogStorage{
		entries: make([]*LogEntry, maxSize),
		maxSize: maxSize,
		head:    0,
		tail:    0,
		size:    0,
	}
}

func (b *BoundedLogStorage) Add(entry *LogEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries[b.tail] = entry
	b.tail = (b.tail + 1) % b.maxSize
	
	if b.size < b.maxSize {
		b.size++
	} else {
		b.head = (b.head + 1) % b.maxSize
	}
}

func (b *BoundedLogStorage) GetAll() []*LogEntry {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*LogEntry, b.size)
	if b.size == 0 {
		return result
	}

	if b.head < b.tail {
		copy(result, b.entries[b.head:b.tail])
	} else {
		n := copy(result, b.entries[b.head:])
		copy(result[n:], b.entries[:b.tail])
	}
	return result
}

func (b *BoundedLogStorage) Size() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.size
}

type ConcurrentTree struct {
	mu   sync.RWMutex
	tree map[string]map[string][]*LogEntry
}

func NewConcurrentTree() *ConcurrentTree {
	return &ConcurrentTree{
		tree: make(map[string]map[string][]*LogEntry),
	}
}

func (c *ConcurrentTree) AddEntry(date, service string, entry *LogEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tree[date] == nil {
		c.tree[date] = make(map[string][]*LogEntry)
	}
	c.tree[date][service] = append(c.tree[date][service], entry)
}

func (c *ConcurrentTree) GetTree() map[string]map[string][]*LogEntry {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]map[string][]*LogEntry)
	for date, services := range c.tree {
		result[date] = make(map[string][]*LogEntry)
		for service, entries := range services {
			entriesCopy := make([]*LogEntry, len(entries))
			copy(entriesCopy, entries)
			result[date][service] = entriesCopy
		}
	}
	return result
}

func (c *ConcurrentTree) GetDates() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	dates := make([]string, 0, len(c.tree))
	for date := range c.tree {
		dates = append(dates, date)
	}
	return dates
}

type xzReader struct {
	io.Reader
	cmd *exec.Cmd
}

func (x *xzReader) Close() error {
	if x.cmd.Process != nil {
		if err := x.cmd.Process.Signal(os.Interrupt); err != nil {
			x.cmd.Process.Kill()
		}
	}
	err := x.cmd.Wait()
	if err != nil {
		return fmt.Errorf("xz command failed: %w", err)
	}
	return nil
}

func validateCompressedFile(original io.Reader, maxSize int64) (io.Reader, error) {
	var buf bytes.Buffer
	limitReader := io.LimitReader(original, maxSize+1)
	tee := io.TeeReader(limitReader, &buf)

	n, err := io.Copy(io.Discard, tee)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("validation read failed: %w", err)
	}

	if n > maxSize {
		return nil, errors.New("file appears to be a decompression bomb")
	}

	return io.MultiReader(&buf, original), nil
}

type LogParser struct {
	CurrentYear         int
	Verbose             bool
	UseRSyslogDetection bool
	RSyslogInfo         *RSyslogInfo
	CompiledPatterns    []PatternInfo
}

func NewLogParser(currentYear int, verbose, useRSyslogDetection bool) (*LogParser, error) {
	parser := &LogParser{
		CurrentYear:         currentYear,
		Verbose:             verbose,
		UseRSyslogDetection: useRSyslogDetection,
	}

	if useRSyslogDetection {
		parser.RSyslogInfo = &RSyslogInfo{}
		detected, err := parser.RSyslogInfo.DetectRSyslogInfo()
		if err != nil && verbose {
			slog.Warn("failed to detect rsyslog", "error", err)
		}
		if detected && verbose {
			slog.Info("detected rsyslogd version", "version", parser.RSyslogInfo.Version)
		}
	}

	parser.CompiledPatterns = parser.compilePatterns()
	return parser, nil
}

func (l *LogParser) compilePatterns() []PatternInfo {
	if l.RSyslogInfo != nil {
		return l.RSyslogInfo.GetRecommendedPatterns()
	}

	return []PatternInfo{
		{
			Pattern:     traditionalPattern,
			Type:        "traditional",
			Description: "Basic syslog format",
		},
		{
			Pattern:     traditionalSimplePattern,
			Type:        "traditional_simple",
			Description: "Simple syslog format",
		},
		{
			Pattern:     iso8601Pattern,
			Type:        "iso8601",
			Description: "ISO 8601 timestamp format",
		},
	}
}

func (l *LogParser) parseIsoTimestamp(tsStr string) (*time.Time, error) {
	tsStr = strings.Replace(tsStr, " ", "T", 1)

	formats := []string{
		"2006-01-02T15:04:05.999999Z",
		"2006-01-02T15:04:05Z",
		"2006-01-02T15:04:05.999999",
		"2006-01-02T15:04:05",
		"2006-01-02T15:04:05-0700",
		"2006-01-02T15:04:05.999999-0700",
	}

	var lastErr error
	for _, format := range formats {
		if t, err := time.Parse(format, tsStr); err == nil {
			return &t, nil
		} else {
			lastErr = err
		}
	}
	return nil, fmt.Errorf("failed to parse timestamp %q: %w", tsStr, lastErr)
}

func (l *LogParser) ParseLine(line string, now, cutoffDate time.Time) (*LogEntry, error) {
	if !l.isLikelyLogLine(line) {
		return nil, errors.New("not a log line")
	}

	for _, patternInfo := range l.CompiledPatterns {
		match := patternInfo.Pattern.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		groupDict := make(map[string]string)
		for i, name := range patternInfo.Pattern.SubexpNames() {
			if i > 0 && i <= len(match) && name != "" {
				groupDict[name] = match[i]
			}
		}

		timestamp, err := l.extractTimestamp(groupDict, patternInfo.Type, now)
		if err != nil {
			return nil, fmt.Errorf("timestamp extraction failed: %w", err)
		}
		if timestamp == nil || timestamp.Before(cutoffDate) || timestamp.After(now.Add(24*time.Hour)) {
			return nil, errors.New("timestamp out of range")
		}

		return &LogEntry{
			Timestamp: *timestamp,
			Service:   strings.TrimSpace(groupDict["service"]),
			Message:   strings.TrimSpace(groupDict["message"]),
			Level:     groupDict["level"],
			Host:      groupDict["host"],
			PID:       groupDict["pid"],
			RawLine:   line,
		}, nil
	}

	return nil, errors.New("no pattern matched")
}

func (l *LogParser) isLikelyLogLine(line string) bool {
	if line == "" || len(line) < 15 {
		return false
	}

	if len(line) >= 3 {
		firstThree := line[:3]
		if _, exists := months[firstThree]; exists {
			return true
		}
	}

	return regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`).MatchString(line)
}

func (l *LogParser) extractTimestamp(groupDict map[string]string, patternType string, now time.Time) (*time.Time, error) {
	if patternType == "iso8601" || patternType == "journald" || patternType == "rainerscript_enhanced" {
		return l.parseIsoTimestamp(groupDict["timestamp"])
	}

	month := groupDict["month"]
	day := groupDict["day"]
	timeStr := groupDict["time"]

	year := now.Year()
	if monthNum, exists := map[string]int{
		"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
		"Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
	}[month]; exists {
		currentMonth := int(now.Month())
		if monthNum > currentMonth && monthNum-currentMonth > 6 {
			year--
		} else if monthNum < currentMonth && currentMonth-monthNum > 6 {
			year++
		}
	}

	var baseTime string
	var microseconds int
	if strings.Contains(timeStr, ".") {
		timeParts := strings.Split(timeStr, ".")
		baseTime = timeParts[0]
		microStr := timeParts[1]
		if len(microStr) > 6 {
			microStr = microStr[:6]
		}
		microStr = microStr + strings.Repeat("0", 6-len(microStr))
		var err error
		microseconds, err = strconv.Atoi(microStr)
		if err != nil {
			return nil, fmt.Errorf("invalid microseconds: %s", microStr)
		}
	} else {
		baseTime = timeStr
		microseconds = 0
	}

	tsStr := fmt.Sprintf("%d %s %s %s", year, month, day, baseTime)
	t, err := time.Parse("2006 Jan 2 15:04:05", tsStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse timestamp: %w", err)
	}
	result := time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), microseconds*1000, t.Location())
	return &result, nil
}

func (l *LogParser) GetParserInfo() map[string]interface{} {
	patternTypes := make([]string, len(l.CompiledPatterns))
	patternDescriptions := make([]string, len(l.CompiledPatterns))

	for i, pattern := range l.CompiledPatterns {
		patternTypes[i] = pattern.Type
		patternDescriptions[i] = pattern.Description
	}

	info := map[string]interface{}{
		"patterns_loaded":      len(l.CompiledPatterns),
		"pattern_types":        patternTypes,
		"pattern_descriptions": patternDescriptions,
	}

	if l.RSyslogInfo != nil {
		info["rsyslog_detected"] = true
		info["rsyslog_version"] = l.RSyslogInfo.Version
		info["rsyslog_features"] = l.RSyslogInfo.Features
		info["recommendations"] = l.RSyslogInfo.GetConfigRecommendations()
	} else {
		info["rsyslog_detected"] = false
	}

	return info
}

type RSyslogAnalyzer struct {
	Tree            *ConcurrentTree
	Config          *AnalyzerConfig
	LogFile         string
	CurrentYear     int
	Parser          *LogParser
	AnalysisResults *AnalysisResults
	Plugins         []AnalysisPlugin
	ProcessedLines  int64
	ParsedEntries   int64
	memoryWarning   int32
	storage         *BoundedLogStorage
}

func NewRSyslogAnalyzer(logFile string, config *AnalyzerConfig) (*RSyslogAnalyzer, error) {
	if config == nil {
		config = NewDefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	currentYear := time.Now().Year()
	parser, err := NewLogParser(currentYear, config.Verbose, config.UseRSyslogDetection)
	if err != nil {
		return nil, fmt.Errorf("failed to create parser: %w", err)
	}

	analyzer := &RSyslogAnalyzer{
		Tree:            NewConcurrentTree(),
		Config:          config,
		LogFile:         logFile,
		CurrentYear:     currentYear,
		Parser:          parser,
		AnalysisResults: NewAnalysisResults(),
		Plugins:         []AnalysisPlugin{NewErrorClusterPlugin()},
		storage:         NewBoundedLogStorage(config.MaxMemoryEntries),
		memoryWarning:   0,
	}

	if analyzer.LogFile == "" {
		analyzer.LogFile = analyzer.findLogFile()
	}

	return analyzer, nil
}

func (r *RSyslogAnalyzer) isReadableLog(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().IsRegular()
}

func (r *RSyslogAnalyzer) getRecentDates() []string {
	dates := make([]string, RecentDaysCount)
	for i := 0; i < RecentDaysCount; i++ {
		date := time.Now().AddDate(0, 0, -i).Format("20060102")
		dates[i] = date
	}
	return dates
}

func (r *RSyslogAnalyzer) findLogFile() string {
	candidates := make([]struct {
		Path  string
		Mtime time.Time
	}, 0)

	for _, path := range defaultSyslogPaths {
		if r.isReadableLog(path) {
			if info, err := os.Stat(path); err == nil {
				candidates = append(candidates, struct {
					Path  string
					Mtime time.Time
				}{Path: path, Mtime: info.ModTime()})
			}
		}

		patterns := make([]string, 0)
		for _, ext := range []string{"1", "2", "3", "0"} {
			patterns = append(patterns, path+"."+ext)
		}
		for _, date := range r.getRecentDates() {
			patterns = append(patterns, path+"-"+date)
		}

		for _, pattern := range patterns {
			if r.isReadableLog(pattern) {
				if info, err := os.Stat(pattern); err == nil {
					candidates = append(candidates, struct {
						Path  string
						Mtime time.Time
					}{Path: pattern, Mtime: info.ModTime()})
				}
			}
		}
	}

	for _, candidate := range candidates {
		for _, ext := range []string{".gz", ".bz2", ".xz"} {
			compressedPath := candidate.Path + ext
			if r.isReadableLog(compressedPath) {
				if info, err := os.Stat(compressedPath); err == nil {
					candidates = append(candidates, struct {
						Path  string
						Mtime time.Time
					}{Path: compressedPath, Mtime: info.ModTime()})
				}
			}
		}
	}

	if len(candidates) == 0 {
		slog.Warn("no standard syslog file found or insufficient permissions")
		return ""
	}

	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].Mtime.After(candidates[j].Mtime)
	})

	selected := candidates[0].Path
	slog.Info("using log file", "path", selected)
	return selected
}

func (r *RSyslogAnalyzer) isSafePath(path string) bool {
	originalPath := path
	for i := 0; i < MaxPointerJumps; i++ {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return false
		}
		path = resolved
	}

	resolved := filepath.Clean(path)

	for _, allowed := range allowedDirs {
		allowed = filepath.Clean(allowed)
		if strings.HasPrefix(resolved, allowed) {
			rel, err := filepath.Rel(allowed, resolved)
			if err == nil && !strings.Contains(rel, "..") {
				cleanRel := filepath.Clean(rel)
				if cleanRel == rel {
					return true
				}
			}
		}
	}

	slog.Warn("path not in allowed directories", "path", originalPath, "resolved", resolved)
	return false
}

func (r *RSyslogAnalyzer) openLogFile(filePath string) (io.ReadCloser, error) {
	if strings.Contains(filePath, "..") || strings.ContainsAny(filePath, "$`") {
		return nil, SecurityError{Message: fmt.Sprintf("potentially dangerous path: %s", filePath)}
	}

	resolvedPath, err := filepath.EvalSymlinks(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve symlinks: %w", err)
	}

	if !r.isSafePath(resolvedPath) {
		return nil, SecurityError{Message: fmt.Sprintf("access to %s not allowed", filePath)}
	}

	info, err := os.Stat(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	fileSizeMB := info.Size() / (1024 * 1024)
	if fileSizeMB > int64(r.Config.MaxFileSizeMB) {
		return nil, SecurityError{Message: fmt.Sprintf("file too large: %dMB > %dMB limit", fileSizeMB, r.Config.MaxFileSizeMB)}
	}

	file, err := os.Open(resolvedPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	if strings.HasSuffix(filePath, ".gz") {
		reader, err := gzip.NewReader(file)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		validatedReader, err := validateCompressedFile(reader, MaxDecompressedSize)
		if err != nil {
			reader.Close()
			return nil, fmt.Errorf("gzip validation failed: %w", err)
		}
		return struct {
			io.Reader
			io.Closer
		}{
			Reader: validatedReader,
			Closer: reader,
		}, nil
	} else if strings.HasSuffix(filePath, ".bz2") {
		reader := bzip2.NewReader(file)
		validatedReader, err := validateCompressedFile(reader, MaxDecompressedSize)
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("bzip2 validation failed: %w", err)
		}
		return struct {
			io.Reader
			io.Closer
		}{
			Reader: validatedReader,
			Closer: file,
		}, nil
	} else if strings.HasSuffix(filePath, ".xz") {
		cmd := exec.Command("xz", "-dc", resolvedPath)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			file.Close()
			return nil, fmt.Errorf("xz compression not supported and system xz command unavailable: %w", err)
		}
		if err := cmd.Start(); err != nil {
			file.Close()
			return nil, fmt.Errorf("failed to start xz command: %w", err)
		}
		return &xzReader{stdout, cmd}, nil
	}

	return file, nil
}

func (r *RSyslogAnalyzer) LoadLogs() error {
	return r.LoadLogsWithContext(context.Background())
}

func (r *RSyslogAnalyzer) LoadLogsWithContext(ctx context.Context) error {
	if r.LogFile == "" {
		return fmt.Errorf("no log file specified or found")
	}

	if _, err := os.Stat(r.LogFile); err != nil {
		return fmt.Errorf("log file does not exist: %s", r.LogFile)
	}

	info, err := os.Stat(r.LogFile)
	if err != nil {
		return fmt.Errorf("cannot access log file: %w", err)
	}

	if info.Size() > 1024*1024 {
		fmt.Print("Parsing logs...")
		defer fmt.Println(" done")
	}

	type openResult struct {
		reader io.ReadCloser
		err    error
	}
	
	resultCh := make(chan openResult, 1)
	go func() {
		reader, err := r.openLogFile(r.LogFile)
		resultCh <- openResult{reader, err}
	}()

	var reader io.ReadCloser
	select {
	case <-ctx.Done():
		return ctx.Err()
	case res := <-resultCh:
		if res.err != nil {
			return fmt.Errorf("cannot read log file: %w", res.err)
		}
		reader = res.reader
	}
	defer reader.Close()

	now := time.Now()
	cutoffDate := now.AddDate(0, 0, -r.Config.MaxDays)

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, MaxLineLength)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		atomic.AddInt64(&r.ProcessedLines, 1)
		line := scanner.Text()
		entry, err := r.Parser.ParseLine(strings.TrimSpace(line), now, cutoffDate)
		if err != nil && r.Config.Verbose {
			slog.Debug("failed to parse line", "line", line, "error", err)
		}
		if entry != nil {
			r.processEntry(entry)
		}
	}

	if err := scanner.Err(); err != nil && r.Config.Verbose {
		slog.Warn("scanner error", "error", err)
	}

	if r.Config.Verbose {
		processed := atomic.LoadInt64(&r.ProcessedLines)
		parsed := atomic.LoadInt64(&r.ParsedEntries)
		successRate := 0.0
		if processed > 0 {
			successRate = float64(parsed) / float64(processed) * 100
		}
		slog.Info("processing complete",
			"processed_lines", processed,
			"parsed_entries", parsed,
			"success_rate", successRate)
	}

	return nil
}

func (r *RSyslogAnalyzer) processEntry(entry *LogEntry) {
	if r.storage.Size() >= r.Config.MaxMemoryEntries {
		if atomic.CompareAndSwapInt32(&r.memoryWarning, 0, 1) {
			slog.Warn("memory limit reached", "limit", r.Config.MaxMemoryEntries)
		}
		return
	}

	atomic.AddInt64(&r.ParsedEntries, 1)
	dateKey := entry.Timestamp.Format("2006-01-02")
	r.Tree.AddEntry(dateKey, entry.Service, entry)
	r.storage.Add(entry)

	if r.Config.EnableAnalysis {
		r.AnalysisResults.Update(entry)
	}

	for _, plugin := range r.Plugins {
		plugin.ProcessEntry(entry)
	}
}

func (r *RSyslogAnalyzer) BuildTree() {
	tree := r.Tree.GetTree()

	for _, services := range tree {
		for _, logs := range services {
			sort.Slice(logs, func(i, j int) bool {
				return logs[i].Timestamp.Before(logs[j].Timestamp)
			})
		}
	}

	if len(tree) > 0 && r.Config.EnableAnalysis {
		dates := r.Tree.GetDates()
		sort.Strings(dates)
		r.AnalysisResults.DateRange = [2]string{dates[0], dates[len(dates)-1]}
	}
}

func (r *RSyslogAnalyzer) DisplaySystemInfo() {
	parserInfo := r.Parser.GetParserInfo()

	if r.Config.ColorOutput {
		r.displayColorSystemInfo(parserInfo)
	} else {
		r.displayTextSystemInfo(parserInfo)
	}
}

func (r *RSyslogAnalyzer) displayColorSystemInfo(parserInfo map[string]interface{}) {
	fmt.Println("\n=== System Information ===")
	fmt.Printf("Patterns loaded: %v\n", parserInfo["patterns_loaded"])
	fmt.Printf("Pattern types: %v\n", strings.Join(parserInfo["pattern_types"].([]string), ", "))
	fmt.Printf("RSyslog detected: %v\n", parserInfo["rsyslog_detected"])

	if parserInfo["rsyslog_detected"].(bool) {
		fmt.Printf("RSyslog version: %v\n", parserInfo["rsyslog_version"])
		fmt.Printf("RainerScript bits: %v\n", r.Parser.RSyslogInfo.RainerscriptBits)
	}

	fmt.Println("\nPattern Descriptions:")
	for i, desc := range parserInfo["pattern_descriptions"].([]string) {
		fmt.Printf("  %d. %s\n", i+1, desc)
	}

	if recommendations, ok := parserInfo["recommendations"].(map[string]string); ok {
		fmt.Println("\nRecommendations:")
		for _, recommendation := range recommendations {
			fmt.Printf("  • %s\n", recommendation)
		}
	}
}

func (r *RSyslogAnalyzer) displayTextSystemInfo(parserInfo map[string]interface{}) {
	fmt.Println("\nSystem Information:")
	fmt.Printf("  Patterns loaded: %v\n", parserInfo["patterns_loaded"])
	fmt.Printf("  Pattern types: %v\n", strings.Join(parserInfo["pattern_types"].([]string), ", "))
	fmt.Printf("  RSyslog detected: %v\n", parserInfo["rsyslog_detected"])

	if parserInfo["rsyslog_detected"].(bool) {
		fmt.Printf("  RSyslog version: %v\n", parserInfo["rsyslog_version"])
		fmt.Printf("  RainerScript bits: %v\n", r.Parser.RSyslogInfo.RainerscriptBits)
	}

	fmt.Println("\nPattern Descriptions:")
	for i, desc := range parserInfo["pattern_descriptions"].([]string) {
		fmt.Printf("  %d. %s\n", i+1, desc)
	}

	if recommendations, ok := parserInfo["recommendations"].(map[string]string); ok {
		fmt.Println("\nRecommendations:")
		for _, recommendation := range recommendations {
			fmt.Printf("  • %s\n", recommendation)
		}
	}
}

func (r *RSyslogAnalyzer) DisplayTree() {
	tree := r.Tree.GetTree()

	if len(tree) == 0 {
		fmt.Println("No logs to display.")
		return
	}

	if r.Config.ColorOutput {
		fmt.Println("\n=== Syslog Analysis Tree ===")
	} else {
		fmt.Println("Syslog Analysis Tree")
		fmt.Println(strings.Repeat("=", 50))
	}

	dates := r.Tree.GetDates()
	sort.Strings(dates)

	for _, date := range dates {
		fmt.Printf("\n%s\n", date)
		services := tree[date]

		serviceNames := make([]string, 0, len(services))
		for service := range services {
			serviceNames = append(serviceNames, service)
		}
		sort.Strings(serviceNames)

		for i, service := range serviceNames {
			logs := services[service]
			errorCount := 0
			for _, log := range logs {
				if log.IsError() {
					errorCount++
				}
			}

			serviceDisplay := service
			if errorCount > 0 {
				serviceDisplay += fmt.Sprintf(" [errors: %d]", errorCount)
			}

			connector := "├── "
			if i == len(serviceNames)-1 {
				connector = "└── "
			}
			fmt.Printf("%s%s\n", connector, serviceDisplay)
			r.displayServiceLogs(logs, i == len(serviceNames)-1)
		}
	}
	fmt.Println()
}

func (r *RSyslogAnalyzer) displayServiceLogs(logs []*LogEntry, isLastService bool) {
	displayedCount := len(logs)
	if displayedCount > r.Config.MaxLinesPerService {
		displayedCount = r.Config.MaxLinesPerService
	}

	for i, log := range logs[:displayedCount] {
		isLastLog := i == displayedCount-1
		prefix := "│   "
		if isLastService {
			prefix = "    "
		}
		if isLastLog {
			prefix += "└── "
		} else {
			prefix += "├── "
		}

		r.displayLogEntry(log, prefix, isLastLog)
	}

	if len(logs) > r.Config.MaxLinesPerService {
		overflowCount := len(logs) - r.Config.MaxLinesPerService
		errorCount := 0
		for _, log := range logs[r.Config.MaxLinesPerService:] {
			if log.IsError() {
				errorCount++
			}
		}

		overflowMsg := fmt.Sprintf("... (%d more logs", overflowCount)
		if errorCount > 0 {
			overflowMsg += fmt.Sprintf(", %d errors", errorCount)
		}
		overflowMsg += ")"

		prefix := "│   "
		if isLastService {
			prefix = "    "
		}
		fmt.Printf("%s└── %s\n", prefix, overflowMsg)
	}
}

func wrapText(text string, width int) []string {
	if len(text) <= width {
		return []string{text}
	}

	lines := []string{}
	currentLine := ""
	words := strings.Fields(text)

	for _, word := range words {
		if len(currentLine)+len(word)+1 <= width {
			if currentLine != "" {
				currentLine += " " + word
			} else {
				currentLine = word
			}
		} else {
			if currentLine != "" {
				lines = append(lines, currentLine)
			}
			currentLine = word
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}

func (r *RSyslogAnalyzer) displayLogEntry(log *LogEntry, prefix string, isLast bool) {
	timestamp := log.Timestamp.Format("15:04:05")
	levelIndicator := ""
	if log.Level != "" {
		levelIndicator = "[" + log.Level + "] "
	}

	var messageLines []string
	var truncation string
	if r.Config.ShowFullLines {
		messageLines = []string{log.Message}
		truncation = ""
	} else if r.Config.WrapLines {
		wrapWidth := 40
		if r.Config.TruncateLength-len(prefix)-len(timestamp)-len(levelIndicator)-3 > wrapWidth {
			wrapWidth = r.Config.TruncateLength - len(prefix) - len(timestamp) - len(levelIndicator) - 3
		}
		messageLines = wrapText(log.Message, wrapWidth)
		truncation = ""
	} else {
		if len(log.Message) > r.Config.TruncateLength {
			messageLines = []string{log.Message[:r.Config.TruncateLength]}
			truncation = "..."
		} else {
			messageLines = []string{log.Message}
			truncation = ""
		}
	}

	firstLine := fmt.Sprintf("%s[%s] %s%s%s", prefix, timestamp, levelIndicator, messageLines[0], truncation)
	r.printLine(firstLine, r.getStyleForLog(log))

	if r.Config.WrapLines && len(messageLines) > 1 {
		connector := "       "
		if !isLast {
			connector = "│      "
		}
		for _, line := range messageLines[1:] {
			fmt.Printf("│   %s%s\n", connector, line)
		}
	}
}

func (r *RSyslogAnalyzer) getStyleForLog(log *LogEntry) string {
	if log.Level != "" {
		levelStyles := map[string]string{
			"ERROR":    "\033[31m",
			"ERR":      "\033[31m",
			"FATAL":    "\033[1;31m",
			"WARN":     "\033[33m",
			"WARNING":  "\033[33m",
			"INFO":     "\033[32m",
			"DEBUG":    "\033[34m",
			"CRIT":     "\033[1;31m",
			"CRITICAL": "\033[1;31m",
		}
		if style, ok := levelStyles[strings.ToUpper(log.Level)]; ok {
			return style
		}
	}

	errorIndicators := []string{"error", "failed", "failure", "exception", "critical"}
	lowerMessage := strings.ToLower(log.Message)
	for _, indicator := range errorIndicators {
		if strings.Contains(lowerMessage, indicator) {
			return "\033[31m"
		}
	}

	return "\033[0m"
}

func (r *RSyslogAnalyzer) printLine(text, style string) {
	if r.Config.ColorOutput && style != "" {
		fmt.Printf("%s%s\033[0m\n", style, text)
	} else {
		fmt.Println(text)
	}
}

func (r *RSyslogAnalyzer) DisplaySummary() {
	if r.AnalysisResults.TotalEntries == 0 {
		fmt.Println("No logs found.")
		return
	}

	if r.Config.ColorOutput {
		r.displayColorSummary()
	} else {
		r.displayTextSummary()
	}
}

func (r *RSyslogAnalyzer) displayColorSummary() {
	fmt.Println("\n=== Log Analysis Summary ===")
	fmt.Printf("Total entries: %d\n", r.AnalysisResults.TotalEntries)
	fmt.Printf("Unique services: %d\n", len(r.AnalysisResults.UniqueServices))
	fmt.Printf("Date range: %s to %s\n", r.AnalysisResults.DateRange[0], r.AnalysisResults.DateRange[1])
	fmt.Printf("Days with logs: %d\n", len(r.Tree.GetDates()))
	fmt.Printf("Error count: %d\n", r.AnalysisResults.ErrorCount)

	topServices := make([]struct {
		Service string
		Count   int
	}, 0, len(r.AnalysisResults.ServiceCounts))
	for service, count := range r.AnalysisResults.ServiceCounts {
		topServices = append(topServices, struct {
			Service string
			Count   int
		}{Service: service, Count: count})
	}
	sort.Slice(topServices, func(i, j int) bool {
		return topServices[i].Count > topServices[j].Count
	})
	if len(topServices) > MaxTopServices {
		topServices = topServices[:MaxTopServices]
	}
	servicesStr := ""
	for i, s := range topServices {
		if i > 0 {
			servicesStr += ", "
		}
		servicesStr += fmt.Sprintf("%s (%d)", s.Service, s.Count)
	}
	fmt.Printf("Top services: %s\n", servicesStr)

	if len(r.AnalysisResults.LevelDistribution) > 0 {
		fmt.Println("\nLog Level Distribution:")
		levels := make([]struct {
			Level string
			Count int
		}, 0, len(r.AnalysisResults.LevelDistribution))
		for level, count := range r.AnalysisResults.LevelDistribution {
			levels = append(levels, struct {
				Level string
				Count int
			}{Level: level, Count: count})
		}
		sort.Slice(levels, func(i, j int) bool {
			return levels[i].Count > levels[j].Count
		})
		for _, level := range levels {
			fmt.Printf("  %s: %d\n", level.Level, level.Count)
		}
	}

	for _, plugin := range r.Plugins {
		results := plugin.GetResults()
		if len(results) > 0 {
			fmt.Printf("\nPlugin: %T\n", plugin)
			for k, v := range results {
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
	}
}

func (r *RSyslogAnalyzer) displayTextSummary() {
	fmt.Println("\nSummary:")
	fmt.Printf("  Total entries: %d\n", r.AnalysisResults.TotalEntries)
	fmt.Printf("  Unique services: %d\n", len(r.AnalysisResults.UniqueServices))
	fmt.Printf("  Date range: %s to %s\n", r.AnalysisResults.DateRange[0], r.AnalysisResults.DateRange[1])
	fmt.Printf("  Days with logs: %d\n", len(r.Tree.GetDates()))
	fmt.Printf("  Error count: %d\n", r.AnalysisResults.ErrorCount)

	topServices := make([]struct {
		Service string
		Count   int
	}, 0, len(r.AnalysisResults.ServiceCounts))
	for service, count := range r.AnalysisResults.ServiceCounts {
		topServices = append(topServices, struct {
			Service string
			Count   int
		}{Service: service, Count: count})
	}
	sort.Slice(topServices, func(i, j int) bool {
		return topServices[i].Count > topServices[j].Count
	})
	if len(topServices) > MaxTopServices {
		topServices = topServices[:MaxTopServices]
	}
	servicesStr := ""
	for i, s := range topServices {
		if i > 0 {
			servicesStr += ", "
		}
		servicesStr += fmt.Sprintf("%s (%d)", s.Service, s.Count)
	}
	fmt.Printf("  Top services: %s\n", servicesStr)

	if len(r.AnalysisResults.LevelDistribution) > 0 {
		fmt.Println("  Level distribution:")
		for level, count := range r.AnalysisResults.LevelDistribution {
			fmt.Printf("    %s: %d\n", level, count)
		}
	}
}

func (r *RSyslogAnalyzer) ExportToJSON(filename string) error {
	if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
		return SecurityError{Message: "invalid filename for JSON export"}
	}

	parserInfo := r.Parser.GetParserInfo()

	exportData := map[string]interface{}{
		"metadata": map[string]interface{}{
			"exported_at":          time.Now().Format(time.RFC3339),
			"log_file":             r.LogFile,
			"analysis_period_days": r.Config.MaxDays,
			"parser_info":          parserInfo,
		},
		"summary": map[string]interface{}{
			"total_entries":   r.AnalysisResults.TotalEntries,
			"unique_services": len(r.AnalysisResults.UniqueServices),
			"date_range":      r.AnalysisResults.DateRange,
			"days_with_logs":  len(r.Tree.GetDates()),
			"error_count":     r.AnalysisResults.ErrorCount,
		},
		"service_stats":       r.AnalysisResults.ServiceCounts,
		"level_stats":         r.AnalysisResults.LevelDistribution,
		"hourly_distribution": r.AnalysisResults.HourlyDistribution,
	}

	pluginResults := make(map[string]interface{})
	for _, plugin := range r.Plugins {
		pluginResults[fmt.Sprintf("%T", plugin)] = plugin.GetResults()
	}
	exportData["plugin_results"] = pluginResults

	content, err := json.MarshalIndent(exportData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}

	if err := os.WriteFile(filename, content, 0644); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}

	return nil
}

func (r *RSyslogAnalyzer) ExportToCSV(filename string) error {
	if strings.Contains(filename, "..") || strings.ContainsAny(filename, "/\\") {
		return SecurityError{Message: "invalid filename for CSV export"}
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	if err := writer.Write([]string{"Timestamp", "Service", "Level", "Host", "PID", "Message"}); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	entries := r.storage.GetAll()

	for _, log := range entries {
		if err := writer.Write([]string{
			log.Timestamp.Format(time.RFC3339),
			log.Service,
			log.Level,
			log.Host,
			log.PID,
			log.Message,
		}); err != nil {
			return fmt.Errorf("failed to write row: %w", err)
		}
	}

	return nil
}

func (r *RSyslogAnalyzer) FindErrors(service string) []*LogEntry {
	entries := r.storage.GetAll()
	errors := make([]*LogEntry, 0)

	for _, log := range entries {
		if service != "" && log.Service != service {
			continue
		}
		if log.IsError() {
			errors = append(errors, log)
		}
	}

	sort.Slice(errors, func(i, j int) bool {
		return errors[i].Timestamp.Before(errors[j].Timestamp)
	})

	return errors
}

func (r *RSyslogAnalyzer) FilterLogs(servicePattern, level, messageContains string) []*LogEntry {
	entries := r.storage.GetAll()
	filtered := make([]*LogEntry, 0)
	var serviceRegex *regexp.Regexp
	if servicePattern != "" {
		var err error
		serviceRegex, err = regexp.Compile(servicePattern)
		if err != nil {
			slog.Warn("invalid service pattern regex", "pattern", servicePattern, "error", err)
			return filtered
		}
	}

	for _, log := range entries {
		if serviceRegex != nil && !serviceRegex.MatchString(log.Service) {
			continue
		}
		if level != "" && log.Level != level {
			continue
		}
		if messageContains != "" && !strings.Contains(strings.ToLower(log.Message), strings.ToLower(messageContains)) {
			continue
		}
		filtered = append(filtered, log)
	}

	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].Timestamp.Before(filtered[j].Timestamp)
	})

	return filtered
}

func main() {
	var (
		logFile            = flag.String("log-file", "", "Path to the syslog file (overrides default search).")
		maxDays            = flag.Int("max-days", 30, "Maximum days of logs to keep (default: 30).")
		truncateLength     = flag.Int("truncate-length", 80, "Length to truncate messages (default: 80).")
		showFullLines      = flag.Bool("show-full-lines", false, "Show full log messages without truncation.")
		wrapLines          = flag.Bool("wrap-lines", false, "Wrap long messages across lines.")
		maxLinesPerService = flag.Int("max-lines-per-service", 5, "Maximum lines to show per service (default: 5).")
		noColor            = flag.Bool("no-color", false, "Disable colored output.")
		verbose            = flag.Bool("verbose", false, "Enable verbose output.")
		summary            = flag.Bool("summary", false, "Show summary statistics.")
		systemInfo         = flag.Bool("system-info", false, "Display system and parser information.")
		enableAnalysis     = flag.Bool("enable-analysis", false, "Enable detailed log analysis.")
		export             = flag.String("export", "", "Export analysis results to JSON file.")
		exportCSV          = flag.String("export-csv", "", "Export log data to CSV file.")
		findErrors         = flag.Bool("find-errors", false, "Find and display error logs.")
		service            = flag.String("service", "", "Filter by specific service name.")
		filterService      = flag.String("filter-service", "", "Filter by service name pattern (regex).")
		filterLevel        = flag.String("filter-level", "", "Filter by log level.")
		filterMessage      = flag.String("filter-message", "", "Filter by message content.")
		maxFileSize        = flag.Int("max-file-size", 100, "Maximum file size in MB (default: 100).")
		maxMemoryEntries   = flag.Int("max-memory-entries", 100000, "Maximum log entries to keep in memory (default: 100000).")
		noRSyslogDetection = flag.Bool("no-rsyslog-detection", false, "Disable rsyslog capability detection.")
		configFile         = flag.String("config-file", "", "Load configuration from JSON file.")
		showVersion        = flag.Bool("version", false, "Show version information.")
	)

	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	if *showVersion {
		fmt.Println("RSyslogAnalyzer 4.0.0")
		return
	}

	config := NewDefaultConfig()
	if *configFile != "" {
		if err := config.FromFile(*configFile); err != nil {
			slog.Error("error loading config file", "error", err)
			os.Exit(1)
		}
	} else {
		config.MaxDays = *maxDays
		config.TruncateLength = *truncateLength
		config.ShowFullLines = *showFullLines
		config.WrapLines = *wrapLines
		config.MaxLinesPerService = *maxLinesPerService
		config.ColorOutput = !*noColor
		config.Verbose = *verbose
		config.EnableAnalysis = *enableAnalysis || *summary || *export != ""
		config.MaxFileSizeMB = *maxFileSize
		config.MaxMemoryEntries = *maxMemoryEntries
		config.UseRSyslogDetection = !*noRSyslogDetection
	}

	if err := config.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("starting log analysis",
		"logFile", *logFile,
		"maxDays", *maxDays,
		"maxMemoryEntries", *maxMemoryEntries)

	analyzer, err := NewRSyslogAnalyzer(*logFile, config)
	if err != nil {
		slog.Error("failed to create analyzer", "error", err)
		os.Exit(1)
	}

	if *systemInfo {
		analyzer.DisplaySystemInfo()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := analyzer.LoadLogsWithContext(ctx); err != nil {
		slog.Error("failed to load logs", "error", err)
		os.Exit(1)
	}
	analyzer.BuildTree()

	if *findErrors {
		errors := analyzer.FindErrors(*service)
		if len(errors) > 0 {
			fmt.Printf("\nFound %d error logs:\n", len(errors))
			displayCount := len(errors)
			if displayCount > MaxDisplayErrors {
				displayCount = MaxDisplayErrors
			}
			for _, err := range errors[len(errors)-displayCount:] {
				message := err.Message
				if len(message) > 100 {
					message = message[:100] + "..."
				}
				fmt.Printf("  %s [%s] %s\n", err.Timestamp.Format("2006-01-02 15:04:05"), err.Service, message)
			}
		} else {
			fmt.Println("No error logs found.")
		}
	} else if *filterService != "" || *filterLevel != "" || *filterMessage != "" {
		filtered := analyzer.FilterLogs(*filterService, *filterLevel, *filterMessage)
		if len(filtered) > 0 {
			fmt.Printf("\nFound %d matching logs:\n", len(filtered))
			displayCount := len(filtered)
			if displayCount > MaxDisplayFiltered {
				displayCount = MaxDisplayFiltered
			}
			for _, log := range filtered[len(filtered)-displayCount:] {
				message := log.Message
				if len(message) > 80 {
					message = message[:80] + "..."
				}
				level := log.Level
				if level == "" {
					level = "N/A"
				}
				fmt.Printf("  %s [%s] %s: %s\n", log.Timestamp.Format("2006-01-02 15:04:05"), log.Service, level, message)
			}
		} else {
			fmt.Println("No matching logs found.")
		}
	} else if *summary {
		analyzer.DisplaySummary()
	} else {
		analyzer.DisplayTree()
	}

	if *export != "" {
		if err := analyzer.ExportToJSON(*export); err != nil {
			slog.Error("error exporting to JSON", "error", err)
		} else {
			slog.Info("exported analysis to JSON", "file", *export)
		}
	}

	if *exportCSV != "" {
		if err := analyzer.ExportToCSV(*exportCSV); err != nil {
			slog.Error("error exporting to CSV", "error", err)
		} else {
			slog.Info("exported log data to CSV", "file", *exportCSV)
		}
	}
}
