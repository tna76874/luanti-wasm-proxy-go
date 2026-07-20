package internal

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type ProxyRule struct {
	VirtualIP  string         `yaml:"virtual_ip"`
	RealIP     string         `yaml:"real_ip"`
	RealDomain string         `yaml:"real_domain"`
	PortRegex  string         `yaml:"port_regex"`
	compiled   *regexp.Regexp
}

type ScheduleRule struct {
	Days  []string `yaml:"days"`
	Start string   `yaml:"start"`
	End   string   `yaml:"end"`
}

type Config struct {
	Port             int            `yaml:"port"`
	AllowedSources   []string       `yaml:"allowed_sources"`
	AllowedSchedules []ScheduleRule `yaml:"allowed_schedules"`
	DirectProxies    []ProxyRule    `yaml:"direct_proxies"`
}

var (
	GlobalConfig Config
	logFileMu    sync.Mutex
)

// LogToFile schreibt formatierte Ereignisse sowohl in die Standardausgabe als auch in logs/proxy.log
func LogToFile(format string, v ...interface{}) {
	logFileMu.Lock()
	defer logFileMu.Unlock()

	msg := fmt.Sprintf(format, v...)
	timestampedMsg := fmt.Sprintf("[%s] %s", time.Now().Format("2006-01-02 15:04:05"), msg)

	// Auf Konsole ausgeben
	log.Println(msg)

	// Ordner "logs" automatisch erstellen, falls nicht vorhanden
	logDir := "logs"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return
	}

	// In Datei innerhalb des Ordners schreiben
	logPath := filepath.Join(logDir, "proxy.log")
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		defer f.Close()
		_, _ = f.WriteString(timestampedMsg + "\n")
	}
}

func LoadConfig(path string) {
	file, err := os.ReadFile(path)
	if err != nil {
		LogToFile("Warning: Could not read %s, using defaults: %v", path, err)
		GlobalConfig = Config{
			Port:           8080,
			AllowedSources: []string{"0.0.0.0/0"},
			DirectProxies: []ProxyRule{
				{VirtualIP: "188.40.133.58", RealIP: "188.40.133.58", PortRegex: "^(3[0-9]{4}|40000)$"},
				{VirtualIP: "127.0.0.1", RealIP: "127.0.0.1", PortRegex: "^30000$"},
			},
		}
	} else {
		err = yaml.Unmarshal(file, &GlobalConfig)
		if err != nil {
			log.Fatalf("Failed to parse config.yml: %v", err)
		}
	}

	for i := range GlobalConfig.DirectProxies {
		re, err := regexp.Compile(GlobalConfig.DirectProxies[i].PortRegex)
		if err != nil {
			log.Fatalf("Invalid port_regex '%s': %v", GlobalConfig.DirectProxies[i].PortRegex, err)
		}
		GlobalConfig.DirectProxies[i].compiled = re
	}
}

func CheckTimeAllowed() bool {
	if len(GlobalConfig.AllowedSchedules) == 0 {
		return true
	}

	now := time.Now().UTC()
	currentDay := now.Weekday().String()
	currentTime := now.Format("15:04")

	for _, schedule := range GlobalConfig.AllowedSchedules {
		dayMatch := false
		for _, d := range schedule.Days {
			if d == currentDay {
				dayMatch = true
				break
			}
		}

		if dayMatch {
			if schedule.Start <= schedule.End {
				if currentTime >= schedule.Start && currentTime <= schedule.End {
					return true
				}
			} else {
				if currentTime >= schedule.Start || currentTime <= schedule.End {
					return true
				}
			}
		}
	}

	return false
}

func MatchProxy(vip string, port int) (string, int, bool) {
	for _, rule := range GlobalConfig.DirectProxies {
		if rule.VirtualIP == vip && rule.compiled.MatchString(itoa(port)) {
			targetIP := rule.RealIP
			if rule.RealDomain != "" {
				ips, err := net.LookupIP(rule.RealDomain)
				if err != nil || len(ips) == 0 {
					LogToFile("Failed to resolve domain %s: %v", rule.RealDomain, err)
					return "", 0, false
				}
				for _, ip := range ips {
					if ipv4 := ip.To4(); ipv4 != nil {
						targetIP = ipv4.String()
						break
					}
				}
				if targetIP == "" {
					return "", 0, false
				}
			}
			LogToFile("[ROUTING] Allowed connection from VirtualIP %s to RealIP %s on Port %d", vip, targetIP, port)
			return targetIP, port, true
		}
	}
	LogToFile("[BLOCKED] Proxy request rejected for VirtualIP %s on Port %d (No matching rule)", vip, port)
	return "", 0, false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := [20]byte{}
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}
