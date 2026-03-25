package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	OTG_KEY             = "de82a6ee-d6a7-4566-8dab-2a6f79113664"
	WEBTITAN_CATID      = "61-6373-a000"
	DNS_PORT            = ":53"
	HTTP_PORT           = ":8080"
	WEBTITAN_API        = "https://cloud.webtitan.com/api/v1"
	CATDNS_DOMAIN       = "l5c.io"
	LOGS_FILE           = "logs.json"
	ALERTS_FILE         = "alerts.json"
	BLOCKED_FILE        = "blocked.json"
	ALLOWED_FILE        = "allowed.json"
	BLOCKED_IPS_FILE    = "blocked_ips.json"
	DASH_USER           = "admin"
	DASH_PASS           = "AeroShield2024!"
	STATIC_IP_THRESHOLD = 3
	CLOUDFLARE_PROXY    = "nf2bthbrk3.proxy.cloudflare-gateway.com"
	PROXY_PORT          = "443"
	SERVER_IP           = "66.241.124.85"
	SERVER_HOST         = "frank-vapdeq.fly.dev"
	LIGHTSPEED_PROXY    = "production-ccp-01.lsfilter.com:8043"
)

type QueryLog struct {
	Timestamp string `json:"timestamp"`
	Domain    string `json:"domain"`
	ClientIP  string `json:"client_ip"`
	Action    string `json:"action"`
	Category  string `json:"category"`
	Blocked   bool   `json:"blocked"`
}

type Stats struct {
	TotalQueries   int `json:"total_queries"`
	BlockedQueries int `json:"blocked_queries"`
	AllowedQueries int `json:"allowed_queries"`
	ActiveClients  int `json:"active_clients"`
	BlockedIPs     int `json:"blocked_ips"`
}

type AgentAlert struct {
	Timestamp string `json:"timestamp"`
	ClientIP  string `json:"client_ip"`
	Domain    string `json:"domain"`
	Reason    string `json:"reason"`
	Severity  string `json:"severity"`
}

type IPBehavior struct {
	QueryCount    int
	LastSeen      time.Time
	StaticDNSHits int
	Flagged       bool
	FirstSeen     time.Time
	DNSServers    map[string]int
}

type BlockEvent struct {
	Domain   string
	ClientIP string
	Reason   string
	Category string
}

type ClientReport struct {
	DeviceID    string `json:"device_id"`
	StudentID   string `json:"student_id"`
	URL         string `json:"url"`
	Domain      string `json:"domain"`
	Title       string `json:"title"`
	Keyword     string `json:"keyword"`
	AlertType   string `json:"alert_type"`
	Severity    string `json:"severity"`
	Timestamp   string `json:"timestamp"`
	OS          string `json:"os"`
	Browser     string `json:"browser"`
	ClientIP    string `json:"client_ip"`
	Blocked     bool   `json:"blocked"`
}

type DeviceInfo struct {
	DeviceID  string    `json:"device_id"`
	StudentID string    `json:"student_id"`
	OS        string    `json:"os"`
	Browser   string    `json:"browser"`
	IP        string    `json:"ip"`
	LastSeen  time.Time `json:"last_seen"`
	Online    bool      `json:"online"`
}

var (
	queryLogs      []QueryLog
	agentAlerts    []AgentAlert
	clientReports  []ClientReport
	deviceRegistry = make(map[string]*DeviceInfo)
	stats          Stats
	activeIPs      = make(map[string]time.Time)
	ipBehavior     = make(map[string]*IPBehavior)
	blockedIPs     = make(map[string]bool)
	mu             sync.Mutex
	blockedDomains = make(map[string]bool)
	allowedDomains = make(map[string]bool)
	recentBlocks   = make(map[string]*BlockEvent)
)

var publicDNSServers = map[string]bool{
	"8.8.8.8": true, "8.8.4.4": true,
	"1.1.1.1": true, "1.0.0.1": true,
	"9.9.9.9": true, "208.67.222.222": true,
	"208.67.220.220": true,
	"76.76.19.19": true,
	"94.140.14.14": true,
	"94.140.15.15": true,
}

var mentalHealthKeywords = []string{
	"how to kill myself",
	"how to suicide",
	"want to die",
	"end my life",
	"self harm",
	"cut myself",
	"hurt myself",
	"suicide methods",
	"how to hang",
	"overdose pills",
	"i want to die",
	"kill myself",
	"suicidal",
	"self-harm",
	"selfharm",
}

var mentalHealthDomains = []string{
	"suicide.org",
	"methods.suicide",
	"how-to-suicide.com",
	"selfharm.com",
	"cutting.com",
}

var defaultBlockedDomains = map[string]bool{
	"proxyhog.com": true,
	"ultrasurf.us": true,
	"psiphon.ca": true,
	"hide.me": true,
	"proxysite.com": true,
	"kproxy.com": true,
	"anonymouse.org": true,
	"whoer.net": true,
	"freegate.us": true,
	"betpanda.io": true,
	"bet365.com": true,
	"draftkings.com": true,
	"fanduel.com": true,
	"malware.com": true,
	"phishing.com": true,
	"pornhub.com": true,
	"xvideos.com": true,
	"proxyfree.com": true,
	"hidemyass.com": true,
	"vpnbook.com": true,
	"tunnelbear.com": true,
	"hotspotshield.com": true,
}

var defaultAllowedDomains = map[string]bool{
	"google.com": true,
	"googleapis.com": true,
	"gstatic.com": true,
	"youtube.com": true,
	"cloudflare.com": true,
	"cloudflare-gateway.com": true,
	"microsoft.com": true,
	"office.com": true,
	"zoom.us": true,
	"firebase.google.com": true,
	"webtitan.com": true,
	"lsfilter.com": true,
	"github.com": true,
	"fly.dev": true,
	"frank-vapdeq.fly.dev": true,
}

var fcpsNoProxy = []string{
	"accounts.gstatic.com",
	"accounts.youtube.com",
	"adamexam.com",
	"clients1.google.com",
	"clients2.google.com",
	"clients3.google.com",
	"clients4.google.com",
	"clients5.google.com",
	"clients6.google.com",
	"comodoca.com",
	"csi.gstatic.com",
	"fcps.edu",
	"fonts.gstatic.com",
	"forc-db.github.io",
	"gm1.ggpht.com",
	"i-ready.com",
	"images.google.com",
	"opencfu.sourceforge.net",
	"pearsontestcontent.com",
	"speechstream.net",
	"testnav.com",
	"thawte.com",
	"usertrust.com",
	"verdle.com",
	"vimeo.com",
	"workorder.fcps.edu",
	"wowza.com",
	"127.0.0.1",
	"localhost",
	"lightspeedsystems.app",
	"stagingls.io",
	"developmentls.io",
	"lightspeedsystems.com",
	"lsaccess.me",
	"lsclassroom.com",
	"lsfilter.com",
	"lsmdm.com",
	"lsrelayaccess.com",
	"lsurl.me",
	"relay.school",
	"fonts.googleapis.com",
	"www.googleapis.com",
	"ajax.googleapis.com",
	"googleapis.com",
	"login.i-ready.com",
	"hosted186.renlearn.com",
	"z40.renlearn.com",
	"z40.renlearnrp.com",
	"z46.renlearn.com",
	"z46.renlearnrp.com",
	"hosted298.renlearn.com",
	"realtime.ably.io",
	"z05.renlearn.com",
	"z05.renlearnrp.com",
	"hosted88.renlearn.com",
	"rest.ably.io",
	"lightspeed-realtime.ably.io",
	"a-fallback-lightspeed.ably.io",
	"b-fallback-lightspeed.ably.io",
	"c-fallback-lightspeed.ably.io",
	"accounts.google.com",
	"catchon.com",
	"play.google.com",
	"android.clients.google.com",
}

var fcpsAlwaysProxy = []string{
	"freezenova.games",
	"around.co",
	"codehs.me",
	"github.io",
	"itch.io",
	"onlinehtmlviewer.com",
	"open.spotify.com",
	"quickmath.com",
	"rawcdn.githack.com",
	"repl.co",
	"replit.com",
	"solo.to",
	"spotify.com",
	"talky.io",
	"voidnetwork.space",
	"widgetbot.io",
	"www.spotify.com",
	"www.google.com",
	"www.bing.com",
	"www.youtube.com",
	"m.youtube.com",
}

var fcpsBlockedCats = map[int]bool{
	0: true, 3: true, 4: true,
	8: true, 12: true, 13: true,
	21: true, 28: true, 31: true,
	32: true, 33: true, 39: true,
	42: true, 55: true, 60: true,
	66: true, 67: true, 70: true,
	72: true, 78: true, 85: true,
	94: true, 101: true, 102: true,
	105: true, 112: true, 113: true,
	116: true, 118: true, 126: true,
	134: true, 135: true, 137: true,
	139: true, 140: true, 141: true,
	143: true, 144: true, 145: true,
	202: true, 203: true, 1009: true,
	1011: true, 1012: true, 1014: true,
	1015: true, 1016: true, 1018: true,
	1021: true, 1022: true, 1024: true,
}

var fcpsAlwaysBlockedCats = map[int]bool{
	94: true, 126: true, 137: true,
}

var blockedCategories = map[int]bool{
	3: true, 4: true, 8: true,
	12: true, 13: true, 21: true,
	28: true, 31: true, 32: true,
	39: true, 42: true, 94: true,
	126: true, 137: true, 1009: true,
	1011: true,
}

func saveJSON(filename string,
	data interface{}) {
	bytes, err := json.MarshalIndent(
		data, "", "  ")
	if err != nil {
		log.Printf(
			"[STORAGE] Marshal error %s: %v",
			filename, err)
		return
	}
	if err := ioutil.WriteFile(
		filename, bytes, 0644); err != nil {
		log.Printf(
			"[STORAGE] Write error %s: %v",
			filename, err)
	}
}

func loadJSON(filename string,
	target interface{}) bool {
	if _, err := os.Stat(filename);
		os.IsNotExist(err) {
		return false
	}
	bytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return false
	}
	return json.Unmarshal(bytes, target) == nil
}

func loadAllData() {
	var savedLogs []QueryLog
	if loadJSON(LOGS_FILE, &savedLogs) {
		queryLogs = savedLogs
		log.Printf("[STORAGE] Loaded %d logs",
			len(queryLogs))
	}
	var savedAlerts []AgentAlert
	if loadJSON(ALERTS_FILE, &savedAlerts) {
		agentAlerts = savedAlerts
		log.Printf(
			"[STORAGE] Loaded %d alerts",
			len(agentAlerts))
	}
	var savedBlocked map[string]bool
	if loadJSON(BLOCKED_FILE, &savedBlocked) {
		for k, v := range savedBlocked {
			blockedDomains[k] = v
		}
	}
	var savedAllowed map[string]bool
	if loadJSON(ALLOWED_FILE, &savedAllowed) {
		for k, v := range savedAllowed {
			allowedDomains[k] = v
		}
	}
	var savedBlockedIPs map[string]bool
	if loadJSON(
		BLOCKED_IPS_FILE, &savedBlockedIPs) {
		for k, v := range savedBlockedIPs {
			blockedIPs[k] = v
		}
	}
}

func saveAllData() {
	mu.Lock()
	defer mu.Unlock()
	logs := queryLogs
	if len(logs) > 1000 {
		logs = logs[len(logs)-1000:]
	}
	saveJSON(LOGS_FILE, logs)
	alerts := agentAlerts
	if len(alerts) > 500 {
		alerts = alerts[len(alerts)-500:]
	}
	saveJSON(ALERTS_FILE, alerts)
	saveJSON(BLOCKED_FILE, blockedDomains)
	saveJSON(ALLOWED_FILE, allowedDomains)
	saveJSON(BLOCKED_IPS_FILE, blockedIPs)
}

func autoSave() {
	for {
		time.Sleep(30 * time.Second)
		saveAllData()
		log.Println("[STORAGE] Auto-saved")
	}
}

func checkWebTitan(
	domain string) (bool, string) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
		},
	}
	url := fmt.Sprintf(
		"%s/categorize?domain=%s",
		WEBTITAN_API, domain)
	req, err := http.NewRequest(
		"GET", url, nil)
	if err != nil {
		return false, "unknown"
	}
	req.Header.Set("X-Auth-Token", OTG_KEY)
	req.Header.Set("X-OTG-Key", OTG_KEY)
	req.Header.Set("Content-Type",
		"application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false, "api_unreachable"
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	var result map[string]interface{}
	if err := json.Unmarshal(
		body, &result); err == nil {
		if blocked, ok :=
			result["blocked"].(bool); ok {
			if blocked {
				category := "webtitan_blocked"
				if cat, ok :=
					result["category"].(string); ok {
					category = cat
				}
				return true, category
			}
		}
	}
	if resp.StatusCode == 403 {
		return true, "webtitan_blocked"
	}
	return false, "allowed"
}

func checkCatDNS(domain string) (int, string) {
	filterDomain := domain + ".c-" +
		WEBTITAN_CATID + "." + CATDNS_DOMAIN
	ips, err := net.LookupHost(filterDomain)
	if err != nil || len(ips) == 0 {
		return 0, "uncategorized"
	}
	ip := ips[0]
	if !strings.HasPrefix(ip, "240.0") {
		return 0, "uncategorized"
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0, "uncategorized"
	}
	cat := 0
	fmt.Sscanf(parts[2], "%d", &cat)
	sub := 0
	fmt.Sscanf(parts[3], "%d", &sub)
	category := (cat << 8) | sub
	return category, getCategoryName(category)
}

func getCategoryName(cat int) string {
	categories := map[int]string{
		0: "Uncategorized",
		3: "Adult Content",
		4: "Gambling",
		8: "Malware",
		12: "Phishing",
		13: "Proxy/Anonymizer",
		21: "Violence",
		28: "Drugs",
		31: "Weapons",
		32: "Hate Speech",
		33: "Spam",
		39: "Hacking",
		42: "Illegal Downloads",
		55: "Social Media",
		60: "Gaming",
		66: "Streaming",
		94: "Malware",
		126: "Phishing",
		137: "Botnet",
		1009: "Crypto Mining",
		1011: "Ransomware",
	}
	if name, ok := categories[cat]; ok {
		return name
	}
	return "Unknown"
}

func handleClientReport(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	w.Header().Set(
		"Access-Control-Allow-Methods",
		"POST, OPTIONS")
	w.Header().Set(
		"Access-Control-Allow-Headers",
		"Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(200)
		return
	}

	var report ClientReport
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}
	if err := json.Unmarshal(
		body, &report); err != nil {
		http.Error(w, "bad json", 400)
		return
	}

	report.Timestamp = time.Now().Format(
		time.RFC3339)
	if report.ClientIP == "" {
		report.ClientIP = r.RemoteAddr
		if strings.Contains(
			report.ClientIP, ":") {
			report.ClientIP = strings.Split(
				report.ClientIP, ":")[0]
		}
	}

	mu.Lock()
	clientReports = append(
		clientReports, report)
	if len(clientReports) > 1000 {
		clientReports =
			clientReports[
				len(clientReports)-1000:]
	}

	if deviceRegistry[report.DeviceID] ==
		nil {
		deviceRegistry[report.DeviceID] =
			&DeviceInfo{}
	}
	deviceRegistry[report.DeviceID].DeviceID =
		report.DeviceID
	deviceRegistry[report.DeviceID].StudentID =
		report.StudentID
	deviceRegistry[report.DeviceID].OS =
		report.OS
	deviceRegistry[report.DeviceID].Browser =
		report.Browser
	deviceRegistry[report.DeviceID].IP =
		report.ClientIP
	deviceRegistry[report.DeviceID].LastSeen =
		time.Now()
	deviceRegistry[report.DeviceID].Online =
		true

	if report.AlertType != "" {
		severity := report.Severity
		if severity == "" {
			severity = "medium"
		}
		if report.AlertType ==
			"mental_health" {
			severity = "critical"
		}
		alert := AgentAlert{
			Timestamp: time.Now().Format(
				time.RFC3339),
			ClientIP: report.ClientIP,
			Domain:   report.Domain,
			Reason: fmt.Sprintf(
				"[CLIENT AGENT] %s: %s | "+
					"Device: %s | Student: %s",
				report.AlertType,
				report.Keyword,
				report.DeviceID,
				report.StudentID),
			Severity: severity,
		}
		agentAlerts = append(
			agentAlerts, alert)
		log.Printf(
			"[CLIENT AGENT] %s | %s | %s | %s",
			severity,
			report.DeviceID,
			report.AlertType,
			report.Keyword)
	}
	mu.Unlock()

	json.NewEncoder(w).Encode(
		map[string]string{
			"status": "received",
		})
}

func handleClientRules(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")

	mu.Lock()
	blocked := make([]string, 0)
	for d := range blockedDomains {
		blocked = append(blocked, d)
	}
	allowed := make([]string, 0)
	for d := range allowedDomains {
		allowed = append(allowed, d)
	}
	mu.Unlock()

	rules := map[string]interface{}{
		"blocked_domains":    blocked,
		"allowed_domains":    allowed,
		"mental_health_keywords": mentalHealthKeywords,
		"mental_health_domains": mentalHealthDomains,
		"proxy_endpoint": fmt.Sprintf(
			"https://%s", CLOUDFLARE_PROXY),
		"block_page": fmt.Sprintf(
			"https://%s/blocked", SERVER_HOST),
		"server_host": SERVER_HOST,
		"version":     "3.0",
		"updated":     time.Now().Format(
			time.RFC3339),
	}

	json.NewEncoder(w).Encode(rules)
}

func handleClientReports(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	mu.Lock()
	reports := clientReports
	if len(reports) > 100 {
		reports = reports[len(reports)-100:]
	}
	mu.Unlock()
	json.NewEncoder(w).Encode(reports)
}

func handleDevices(
	w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	mu.Lock()
	devices := make([]*DeviceInfo, 0)
	for _, d := range deviceRegistry {
		if time.Since(d.LastSeen) >
			5*time.Minute {
			d.Online = false
		}
		devices = append(devices, d)
	}
	mu.Unlock()
	json.NewEncoder(w).Encode(devices)
}

func handlePAC(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/x-ns-proxy-autoconfig")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "no-cache")

	mu.Lock()
	extraBlockedList := make([]string, 0)
	for domain := range blockedDomains {
		extraBlockedList = append(
			extraBlockedList,
			`"`+domain+`"`)
	}
	extraAllowedList := make([]string, 0)
	for domain := range allowedDomains {
		extraAllowedList = append(
			extraAllowedList,
			`"`+domain+`"`)
	}
	mu.Unlock()

	noProxyItems := make([]string, 0)
	for _, d := range fcpsNoProxy {
		noProxyItems = append(noProxyItems,
			`"`+d+`"`)
	}
	noProxyStr := strings.Join(
		noProxyItems, ",\n    ")

	alwaysProxyItems := make([]string, 0)
	for _, d := range fcpsAlwaysProxy {
		alwaysProxyItems = append(
			alwaysProxyItems, `"`+d+`"`)
	}
	alwaysProxyStr := strings.Join(
		alwaysProxyItems, ",\n    ")

	fcpsCatItems := make([]string, 0)
	for cat := range fcpsBlockedCats {
		fcpsCatItems = append(fcpsCatItems,
			fmt.Sprintf("%d", cat))
	}
	fcpsCatStr := strings.Join(
		fcpsCatItems, ", ")

	fcpsAlwaysCatItems := make([]string, 0)
	for cat := range fcpsAlwaysBlockedCats {
		fcpsAlwaysCatItems = append(
			fcpsAlwaysCatItems,
			fmt.Sprintf("%d", cat))
	}
	fcpsAlwaysCatStr := strings.Join(
		fcpsAlwaysCatItems, ", ")

	extraBlockedStr := strings.Join(
		extraBlockedList, ",\n    ")
	extraAllowedStr := strings.Join(
		extraAllowedList, ",\n    ")

	pac := fmt.Sprintf(`
function FindProxyForURL(url, host) {
  host = host.toLowerCase();
  var direct = "DIRECT";
  var proxy = "HTTPS %s:%s";
  var customerID = "%s";
  var filterDomain = host + ".c-" +
    customerID + ".%s";

  if (/^www\.google\.([a-z]{2,3}|com?\.[a-z]{2})$/.test(host)) {
    return proxy;
  }

  var no_proxy = [%s];
  for (var i = 0; i < no_proxy.length; i++) {
    var np = no_proxy[i].toLowerCase();
    if (dnsDomainIs(host, "." + np) || host === np) {
      return direct;
    }
  }

  var extra_allowed = [%s];
  for (var i = 0; i < extra_allowed.length; i++) {
    if (dnsDomainIs(host, "." + extra_allowed[i]) || host === extra_allowed[i]) {
      return direct;
    }
  }

  var always_proxy = [%s];
  for (var j = 0; j < always_proxy.length; j++) {
    var ap = always_proxy[j].toLowerCase();
    if (dnsDomainIs(host, "." + ap) || host === ap) {
      return proxy;
    }
  }

  var extra_blocked = [%s];
  for (var j = 0; j < extra_blocked.length; j++) {
    if (dnsDomainIs(host, "." + extra_blocked[j]) || host === extra_blocked[j]) {
      return proxy;
    }
  }

  if (/^(.+\.)?accounts\.google\.(com?\.[a-z]{2}|[a-z]{2,3})$/.test(host) ||
      /^(.+\.)?(googleapis|google|gstatic|gvt1)\.com$/.test(host)) {
    return direct;
  }

  if (isInNet(host,"127.0.0.0","255.0.0.0") ||
      isInNet(host,"10.0.0.0","255.0.0.0") ||
      isInNet(host,"172.16.0.0","255.240.0.0") ||
      isInNet(host,"192.168.0.0","255.255.0.0") ||
      isInNet(host,"169.254.0.0","255.255.0.0")) {
    return direct;
  }

  if (isPlainHostName(host)) return direct;
  if (url.substring(0,4) === "ftp:") return direct;
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)) return direct;

    var always_blocked_cats = [%s];
  var res = dnsResolve(filterDomain.toLowerCase());
  if (res != null && res.substring(0,5) === "240.0") {
    var octets = res.split(".");
    if (octets.length === 4) {
      var cat = (parseInt(octets[2],10) << 8) | parseInt(octets[3],10);
      for (var k = 0; k < always_blocked_cats.length; k++) {
        if (always_blocked_cats[k] === cat) return proxy;
      }
      for (var m = 0; m < blocked_cats.length; m++) {
        if (blocked_cats[m] === cat) return proxy;
      }
    }
  }
  return direct;
}`,
		CLOUDFLARE_PROXY, PROXY_PORT,
		WEBTITAN_CATID,
		CATDNS_DOMAIN,
		noProxyStr,
		extraAllowedStr,
		alwaysProxyStr,
		extraBlockedStr,
		fcpsCatStr,
		fcpsAlwaysCatStr,
	)

	fmt.Fprint(w, pac)
	log.Printf("[PAC] Served to %s",
		r.RemoteAddr)
}

func handleBlockPage(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	site := r.URL.Query().Get("site")
	reason := r.URL.Query().Get("reason")
	clientIP := r.URL.Query().Get("ip")
	category := r.URL.Query().Get("category")

	if clientIP == "" {
		clientIP = r.RemoteAddr
		if strings.Contains(clientIP, ":") {
			clientIP = strings.Split(
				clientIP, ":")[0]
		}
	}
	if site == "" {
		site = r.Host
		if site == "" {
			site = "This site"
		}
	}
	if reason == "" {
		reason = "Policy violation"
	}
	if category == "" {
		category = "Blocked Content"
	}

	mu.Lock()
	recentBlocks[clientIP] = &BlockEvent{
		Domain:   site,
		ClientIP: clientIP,
		Reason:   reason,
		Category: category,
	}
	mu.Unlock()

	page := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>Blocked - AeroTrade</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#000;color:#fff;text-align:center;font-family:Arial,sans-serif;min-height:100vh;display:flex;flex-direction:column}
.header{background:linear-gradient(135deg,#003366,#001a33);padding:30px;border-bottom:3px solid #0066cc}
.header h1{font-size:28px;color:#00d4ff;margin-bottom:5px}
.header h3{color:#aaa;font-size:14px;font-weight:normal}
.blocked{background:linear-gradient(135deg,#001133,#002244);padding:40px 30px;margin:20px auto;max-width:600px;border-radius:15px;border:1px solid #0066cc;width:90%%}
.shield{font-size:60px;margin-bottom:15px}
.oops{color:#ff4444;font-size:18px;margin-bottom:10px}
.site{font-size:28px;font-weight:bold;color:#ff6600;margin:10px 0;word-break:break-all}
.reason-box{background:#001a33;border:1px solid #0066cc;border-radius:8px;padding:15px;margin:15px 0}
.reason-label{color:#888;font-size:12px;text-transform:uppercase;letter-spacing:1px}
.reason-value{color:#ff4444;font-size:18px;font-weight:bold;margin-top:5px}
.info{background:#001122;padding:20px;margin:10px auto;max-width:600px;border-radius:10px;border:1px solid #003366;width:90%%}
.info-row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #002244;font-size:13px}
.info-row:last-child{border-bottom:none}
.info-label{color:#888}
.info-value{color:#00d4ff}
.contact{color:#aaa;font-size:13px;margin-top:15px;padding:15px}
.footer{margin-top:auto;padding:20px;background:#001122;color:#444;font-size:12px;border-top:1px solid #003366}
.footer span{color:#0066cc}
</style>
</head>
<body>
<div class="header">
  <h1>🔐 AeroTrade Global</h1>
  <h3>Network Security &amp; Content Filtering</h3>
</div>
<div class="blocked">
  <div class="shield">🚫</div>
  <p class="oops">Access Blocked!</p>
  <div class="site">%s</div>
  <p style="color:#aaa;font-size:14px;margin:10px 0">
    has been blocked by AeroTrade Network Security
  </p>
  <div class="reason-box">
    <div class="reason-label">Blocked Reason</div>
    <div class="reason-value">%s</div>
  </div>
  <div class="reason-box">
    <div class="reason-label">Content Category</div>
    <div class="reason-value" style="color:#ff9900">%s</div>
  </div>
</div>
<div class="info">
  <div class="info-row">
    <span class="info-label">Your IP Address</span>
    <span class="info-value">%s</span>
  </div>
  <div class="info-row">
    <span class="info-label">Blocked Domain</span>
    <span class="info-value">%s</span>
  </div>
  <div class="info-row">
    <span class="info-label">Time</span>
    <span class="info-value">%s</span>
  </div>
  <div class="info-row">
    <span class="info-label">Protected By</span>
    <span class="info-value">AeroShield DNS + WebTitan OTG</span>
  </div>
  <div class="info-row">
    <span class="info-label">Proxy</span>
    <span class="info-value">Cloudflare Gateway</span>
  </div>
</div>
<div class="contact">
  <p>If you believe this is a mistake,</p>
  <p>contact your network administrator</p>
  <p style="margin-top:10px;color:#0066cc">support@aerotradeglobal.com</p>
</div>
<div class="footer">
  <p><span>AeroTrade Global</span> Network Protection | AeroShield DNS | WebTitan OTG | Cloudflare Gateway</p>
</div>
</body>
</html>`,
		site, reason, category,
		clientIP, site,
		time.Now().Format("2006-01-02 15:04:05 UTC"),
	)
	fmt.Fprint(w, page)
	log.Printf("[BLOCK PAGE] %s for %s",
		clientIP, site)
}

func handleBlockRedirect(
	w http.ResponseWriter,
	r *http.Request) {
	host := r.Host
	if host == "" {
		host = r.URL.Query().Get("host")
	}
	clientIP := r.RemoteAddr
	if strings.Contains(clientIP, ":") {
		clientIP = strings.Split(
			clientIP, ":")[0]
	}
	category := "Policy Violation"
	reason := "This site is blocked by network policy"
	mu.Lock()
	if event, ok := recentBlocks[clientIP]; ok {
		category = event.Category
		reason = event.Reason
	}
	mu.Unlock()
	redirectURL := fmt.Sprintf(
		"https://%s/blocked?site=%s&reason=%s&category=%s&ip=%s",
		SERVER_HOST, host,
		strings.ReplaceAll(reason, " ", "+"),
		strings.ReplaceAll(category, " ", "+"),
		clientIP,
	)
	http.Redirect(w, r, redirectURL, 302)
}

func detectStaticIPBypass(
	clientIP string,
	queryDomain string) {
	mu.Lock()
	defer mu.Unlock()

	if _, exists := ipBehavior[clientIP]; !exists {
		ipBehavior[clientIP] = &IPBehavior{
			FirstSeen:  time.Now(),
			DNSServers: make(map[string]int),
		}
	}
	behavior := ipBehavior[clientIP]
	behavior.QueryCount++
	behavior.LastSeen = time.Now()

	if publicDNSServers[queryDomain] {
		behavior.StaticDNSHits++
	}
	suspiciousDNS := []string{
		"dns.google", "one.one.one.one",
		"dns.cloudflare.com",
		"resolver1.opendns.com",
		"resolver2.opendns.com",
		"dns9.quad9.net", "dns.quad9.net",
	}
	for _, suspDNS := range suspiciousDNS {
		if strings.Contains(
			queryDomain, suspDNS) {
			behavior.StaticDNSHits++
		}
	}
	if behavior.StaticDNSHits >=
		STATIC_IP_THRESHOLD &&
		!behavior.Flagged {
		behavior.Flagged = true
		blockedIPs[clientIP] = true
		agentAlerts = append(agentAlerts,
			AgentAlert{
				Timestamp: time.Now().Format(
					time.RFC3339),
				ClientIP: clientIP,
				Domain:   queryDomain,
				Reason: fmt.Sprintf(
					"Static IP bypass! Alt DNS used %d times. Auto-blocked.",
					behavior.StaticDNSHits),
				Severity: "critical",
			})
		log.Printf(
			"[AGENT] AUTO-BLOCKED %s static bypass",
			clientIP)
	}
}

func smartAgent(
	domain string,
	clientIP string,
	category string,
	blocked bool) {
	mu.Lock()
	defer mu.Unlock()

	severity := "low"
	reason := ""

	for _, kw := range []string{
		"proxy", "vpn", "bypass", "tunnel",
		"anonymo", "unblock", "freedom",
		"torrent", "pirate", "crack",
	} {
		if strings.Contains(domain, kw) {
			severity = "high"
			reason = "Proxy/bypass: " + domain
			break
		}
	}

	for _, kw := range []string{
		"malware", "phish", "botnet",
		"ransomware", "trojan", "virus",
		"exploit", "payload",
	} {
		if strings.Contains(domain, kw) {
			severity = "critical"
			reason = "Malware: " + domain
			break
		}
	}

	for _, kw := range mentalHealthKeywords {
		if strings.Contains(
			strings.ToLower(domain), kw) {
			severity = "critical"
			reason = "Mental health: " + domain
			break
		}
	}

	for _, mhd := range mentalHealthDomains {
		if strings.Contains(domain, mhd) {
			severity = "critical"
			reason = "Mental health domain: " +
				domain
			break
		}
	}

	switch category {
	case "Gambling":
		severity = "medium"
		reason = "Gambling: " + domain
	case "Crypto Mining":
		severity = "high"
		reason = "Crypto mining: " + domain
	case "Adult Content":
		severity = "medium"
		reason = "Adult: " + domain
	case "Botnet":
		severity = "critical"
		reason = "Botnet C2: " + domain
	case "Ransomware":
		severity = "critical"
		reason = "Ransomware: " + domain
	case "Phishing":
		severity = "critical"
		reason = "Phishing: " + domain
	}

	queryCount := 0
	recentTime := time.Now().Add(
		-1 * time.Minute)
	for _, l := range queryLogs {
		t, _ := time.Parse(
			time.RFC3339, l.Timestamp)
		if l.ClientIP == clientIP &&
			t.After(recentTime) {
			queryCount++
		}
	}

	if queryCount > 200 {
		severity = "critical"
		reason = fmt.Sprintf(
			"DDoS: %d q/min from %s",
			queryCount, clientIP)
		if !blockedIPs[clientIP] {
			blockedIPs[clientIP] = true
			log.Printf(
				"[AGENT] AUTO-BLOCKED %s DDoS",
				clientIP)
		}
	} else if queryCount > 100 {
		severity = "high"
		reason = fmt.Sprintf(
			"High rate: %d/min from %s",
			queryCount, clientIP)
	}

	for _, part := range strings.Split(
		domain, ".") {
		if len(part) > 50 {
			severity = "critical"
			reason = "DNS tunnel: " + domain
			if !blockedIPs[clientIP] {
				blockedIPs[clientIP] = true
				log.Printf(
					"[AGENT] AUTO-BLOCKED %s DNS tunnel",
					clientIP)
			}
			break
		}
	}

	if reason != "" {
		agentAlerts = append(agentAlerts,
			AgentAlert{
				Timestamp: time.Now().Format(
					time.RFC3339),
				ClientIP: clientIP,
				Domain:   domain,
				Reason:   reason,
				Severity: severity,
			})
		log.Printf("[AGENT] %s | %s | %s",
			severity, clientIP, reason)
	}
}

func basicAuth(
	next http.HandlerFunc) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request) {
		host := r.RemoteAddr
		if strings.HasPrefix(host, "127.0.0.1") ||
			strings.HasPrefix(host, "[::1]") {
			next(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		if !ok ||
			user != DASH_USER ||
			pass != DASH_PASS {
			w.Header().Set(
				"WWW-Authenticate",
				`Basic realm="AeroShield"`)
			http.Error(w, "Unauthorized", 401)
			return
		}
		next(w, r)
	}
}

func handleDNS(
	w dns.ResponseWriter,
	r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true
	msg.RecursionAvailable = true

	clientIP := w.RemoteAddr().String()
	if strings.Contains(clientIP, "[") {
		clientIP = strings.Split(
			clientIP, "]")[0]
		clientIP = strings.TrimPrefix(
			clientIP, "[")
	} else {
		clientIP = strings.Split(
			clientIP, ":")[0]
	}

	mu.Lock()
	if blockedIPs[clientIP] {
		mu.Unlock()
		log.Printf("[BLOCKED IP] %s", clientIP)
		w.WriteMsg(msg)
		return
	}
	activeIPs[clientIP] = time.Now()
	stats.TotalQueries++
	mu.Unlock()

	for _, question := range r.Question {
		domain := strings.TrimSuffix(
			strings.ToLower(question.Name), ".")

		fmt.Printf("[DNS] %s from %s\n",
			domain, clientIP)

		go detectStaticIPBypass(clientIP, domain)

		blocked := false
		category := "allowed"
		action := "ALLOWED"
		blockReason := ""

		mu.Lock()
		ipBlocked := blockedIPs[clientIP]
		mu.Unlock()

		if ipBlocked {
			blocked = true
			category = "blocked_ip"
			action = "BLOCKED_IP"
			blockReason = "IP address is blocked"
		}

		if !blocked {
			isNoProxy := false
			for _, np := range fcpsNoProxy {
				if strings.HasSuffix(domain, np) ||
					domain == np {
					isNoProxy = true
					break
				}
			}

			if isNoProxy {
				action = "ALLOWED_NOPROXY"
			} else {
				isAllowed := false
				mu.Lock()
				for a := range allowedDomains {
					if strings.HasSuffix(domain, a) {
						isAllowed = true
						break
					}
				}
				mu.Unlock()

				if !isAllowed {
					for _, ap := range fcpsAlwaysProxy {
						if strings.HasSuffix(
							domain, ap) ||
							domain == ap {
							blocked = true
							category = "fcps_always_proxy"
							action = "BLOCKED_FCPS"
							blockReason =
								"FCPS always-proxy list"
							break
						}
					}

					if !blocked {
						mu.Lock()
						for bd := range blockedDomains {
							if strings.HasSuffix(
								domain, bd) {
								blocked = true
								category = "blocked_list"
								action = "BLOCKED"
								blockReason = "On block list"
								break
							}
						}
						mu.Unlock()
					}

					if !blocked {
						wtB, wtC :=
							checkWebTitan(domain)
						if wtB {
							blocked = true
							category = wtC
							action = "BLOCKED_WEBTITAN"
							blockReason =
								"WebTitan: " + wtC
						}
					}

					if !blocked {
						cat, catName :=
							checkCatDNS(domain)
						if fcpsAlwaysBlockedCats[cat] {
							blocked = true
							category = catName
							action =
								"BLOCKED_CATDNS_ALWAYS"
							blockReason =
								"Always blocked: " + catName
						} else if fcpsBlockedCats[cat] {
							blocked = true
							category = catName
							action = "BLOCKED_CATDNS_FCPS"
							blockReason =
								"FCPS category: " + catName
						} else {
							mu.Lock()
							isCatBlocked :=
								blockedCategories[cat]
							mu.Unlock()
							if isCatBlocked {
								blocked = true
								category = catName
								action = "BLOCKED_CATDNS"
								blockReason =
									"Category: " + catName
							}
						}
					}
				}
			}
		}

		if blocked {
			mu.Lock()
			recentBlocks[clientIP] = &BlockEvent{
				Domain:   domain,
				ClientIP: clientIP,
				Reason:   blockReason,
				Category: category,
			}
			mu.Unlock()
		}

		go smartAgent(
			domain, clientIP, category, blocked)

		mu.Lock()
		queryLogs = append(queryLogs, QueryLog{
			Timestamp: time.Now().Format(
				time.RFC3339),
			Domain:   domain,
			ClientIP: clientIP,
			Action:   action,
			Category: category,
			Blocked:  blocked,
		})
		if blocked {
			stats.BlockedQueries++
		} else {
			stats.AllowedQueries++
		}
		mu.Unlock()

		if blocked {
			fmt.Printf(
				"[BLOCKED] %s from %s: %s\n",
				domain, clientIP, blockReason)
			if question.Qtype == dns.TypeA {
				rr, _ := dns.NewRR(
					fmt.Sprintf("%s A %s",
						question.Name, SERVER_IP))
				msg.Answer = append(
					msg.Answer, rr)
			}
		} else {
			fmt.Printf("[ALLOWED] %s from %s\n",
				domain, clientIP)
			upstream := resolveUpstream(question)
			msg.Answer = append(
				msg.Answer, upstream...)
		}
	}
	w.WriteMsg(msg)
}

func resolveUpstream(
	q dns.Question) []dns.RR {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(q.Name, q.Qtype)
	m.RecursionDesired = true
	r, _, err := c.Exchange(m, "1.1.1.1:53")
	if err != nil {
		r, _, err = c.Exchange(m, "8.8.8.8:53")
		if err != nil {
			return nil
		}
	}
	return r.Answer
}

func handleStats(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	mu.Lock()
	stats.ActiveClients = len(activeIPs)
	stats.BlockedIPs = len(blockedIPs)
	s := stats
	mu.Unlock()
	json.NewEncoder(w).Encode(s)
}

func handleLogs(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	mu.Lock()
	logs := queryLogs
	if len(logs) > 100 {
		logs = logs[len(logs)-100:]
	}
	mu.Unlock()
	json.NewEncoder(w).Encode(logs)
}

func handleAlerts(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	mu.Lock()
	alerts := agentAlerts
	mu.Unlock()
	json.NewEncoder(w).Encode(alerts)
}

func handleBlockedIPs(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	mu.Lock()
	ips := make([]string, 0)
	for ip := range blockedIPs {
		ips = append(ips, ip)
	}
	mu.Unlock()
	json.NewEncoder(w).Encode(ips)
}

func handleDashboard(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, dashboardHTML)
}

func handleBlock(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain required", 400)
		return
	}
	mu.Lock()
	blockedDomains[domain] = true
	mu.Unlock()
	saveAllData()
	json.NewEncoder(w).Encode(
		map[string]string{
			"status":  "blocked",
			"domain":  domain,
			"message": domain + " blocked and saved",
		})
}

func handleUnblock(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, "domain required", 400)
		return
	}
	mu.Lock()
	delete(blockedDomains, domain)
	mu.Unlock()
	saveAllData()
	json.NewEncoder(w).Encode(
		map[string]string{
			"status":  "unblocked",
			"domain":  domain,
			"message": domain + " unblocked and saved",
		})
}

func handleBlockIP(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "ip required", 400)
		return
	}
	mu.Lock()
	blockedIPs[ip] = true
	mu.Unlock()
	saveAllData()
	json.NewEncoder(w).Encode(
		map[string]string{
			"status":  "blocked",
			"ip":      ip,
			"message": ip + " blocked and saved",
		})
}

func handleUnblockIP(w http.ResponseWriter,
	r *http.Request) {
	w.Header().Set("Content-Type",
		"application/json")
	w.Header().Set(
		"Access-Control-Allow-Origin", "*")
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "ip required", 400)
		return
	}
	mu.Lock()
	delete(blockedIPs, ip)
	if beh, ok := ipBehavior[ip]; ok {
		beh.Flagged = false
		beh.StaticDNSHits = 0
	}
	mu.Unlock()
	saveAllData()
	json.NewEncoder(w).Encode(
		map[string]string{
			"status":  "unblocked",
			"ip":      ip,
			"message": ip + " unblocked and saved",
		})
}

var dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<title>AeroShield DNS Dashboard</title>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:Arial,sans-serif;background:#0a0a1a;color:#fff}
.header{background:linear-gradient(135deg,#0f3460,#16213e);padding:20px 30px;display:flex;justify-content:space-between;align-items:center;border-bottom:2px solid #00d4ff}
.header h1{color:#00d4ff;font-size:24px}
.badges{display:flex;gap:8px;flex-wrap:wrap;margin-top:5px}
.badge{background:#0f3460;padding:3px 10px;border-radius:5px;font-size:11px;color:#00d4ff}
.status{background:#00ff88;color:#000;padding:5px 15px;border-radius:20px;font-weight:bold;font-size:12px}
.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:15px;padding:20px 30px}
.stat-card{background:#16213e;border:1px solid #0f3460;border-radius:10px;padding:20px;text-align:center}
.stat-card h3{color:#00d4ff;font-size:28px;margin-bottom:5px}
.stat-card p{color:#888;font-size:12px}
.section{margin:0 30px 20px;background:#16213e;border-radius:10px;border:1px solid #0f3460;overflow:hidden}
.section-header{background:#0f3460;padding:15px 20px;display:flex;justify-content:space-between;align-items:center}
.section-header h2{color:#00d4ff;font-size:16px}
table{width:100%;border-collapse:collapse}
th{background:#0a0a2e;padding:10px 15px;text-align:left;color:#00d4ff;font-size:12px}
td{padding:10px 15px;border-bottom:1px solid #0f3460;font-size:12px;color:#ccc}
.blocked{color:#ff4444;font-weight:bold}
.allowed{color:#00ff88;font-weight:bold}
.critical{color:#ff0000;font-weight:bold}
.high{color:#ff6600;font-weight:bold}
.medium{color:#ffaa00}
.low{color:#ffff00}
.mental{color:#ff00ff;font-weight:bold}
.controls{padding:15px 30px;display:flex;gap:10px;flex-wrap:wrap}
.control-group{display:flex;gap:10px;flex:1;min-width:300px}
input{flex:1;padding:10px 15px;background:#16213e;border:1px solid #0f3460;border-radius:8px;color:#fff;font-size:14px}
button{padding:10px 20px;border:none;border-radius:8px;cursor:pointer;font-weight:bold;font-size:13px;white-space:nowrap}
.btn-block{background:#ff4444;color:#fff}
.btn-unblock{background:#00ff88;color:#000}
.btn-block-ip{background:#ff0066;color:#fff}
.btn-unblock-ip{background:#00ccff;color:#000}
.tab-bar{display:flex;gap:5px;padding:15px 30px 0;flex-wrap:wrap}
.tab{padding:10px 20px;background:#16213e;border:1px solid #0f3460;border-bottom:none;border-radius:8px 8px 0 0;cursor:pointer;color:#888;font-size:13px}
.tab.active{background:#0f3460;color:#00d4ff}
.tab-content{display:none}
.tab-content.active{display:block}
.pac-url{background:#001a33;border:1px solid #0066cc;border-radius:8px;padding:15px 20px;margin:15px 30px;font-family:monospace;color:#00d4ff;font-size:13px;word-break:break-all}
.pac-url span{color:#888;font-size:11px;display:block;margin-bottom:5px}
.device-online{color:#00ff88;font-weight:bold}
.device-offline{color:#888}
.alert-mental{background:#1a0033;border-left:4px solid #ff00ff}
</style>
</head>
<body>

<div class="header">
  <div>
    <h1>🛡️ AeroShield DNS v4</h1>
    <div class="badges">
      <span class="badge">WebTitan OTG ✓</span>
      <span class="badge">CatDNS l5c.io ✓</span>
      <span class="badge">FCPS PAC Logic ✓</span>
      <span class="badge">Cloudflare Gateway ✓</span>
      <span class="badge">Client Agent ✓</span>
      <span class="badge">Mental Health ✓</span>
      <span class="badge">frank-vapdeq.fly.dev ✓</span>
    </div>
  </div>
  <div class="status" id="serverStatus">● LIVE</div>
</div>

<div class="pac-url">
  <span>📄 PAC File URL:</span>
  https://frank-vapdeq.fly.dev/proxy.pac
</div>
<div class="pac-url" style="margin-top:-10px">
  <span>🔌 Chrome Extension Rules API:</span>
  https://frank-vapdeq.fly.dev/api/client-rules
</div>
<div class="pac-url" style="margin-top:-10px">
  <span>📡 Client Report API:</span>
  https://frank-vapdeq.fly.dev/api/client-report
</div>

<div class="stats">
  <div class="stat-card">
    <h3 id="total">0</h3>
    <p>Total Queries</p>
  </div>
  <div class="stat-card">
    <h3 id="blocked" style="color:#ff4444">0</h3>
    <p>Blocked</p>
  </div>
  <div class="stat-card">
    <h3 id="allowed" style="color:#00ff88">0</h3>
    <p>Allowed</p>
  </div>
  <div class="stat-card">
    <h3 id="clients" style="color:#ffaa00">0</h3>
    <p>Active Clients</p>
  </div>
  <div class="stat-card">
    <h3 id="blockedips" style="color:#ff0066">0</h3>
    <p>Blocked IPs</p>
  </div>
</div>

<div class="tab-bar">
  <div class="tab active" onclick="showTab('controls',this)">🔧 Controls</div>
  <div class="tab" onclick="showTab('alerts',this)">🤖 Agent Alerts</div>
  <div class="tab" onclick="showTab('logs',this)">📋 Query Logs</div>
  <div class="tab" onclick="showTab('ips',this)">🚫 Blocked IPs</div>
  <div class="tab" onclick="showTab('devices',this)">💻 Devices</div>
  <div class="tab" onclick="showTab('reports',this)">🧠 Client Reports</div>
</div>

<div id="tab-controls" class="tab-content active">
  <div class="controls">
    <div class="control-group">
      <input type="text" id="domainInput" placeholder="Domain (e.g. evil.com)">
      <button class="btn-block" onclick="blockDomain()">🚫 Block Domain</button>
      <button class="btn-unblock" onclick="unblockDomain()">✅ Unblock Domain</button>
    </div>
  </div>
  <div class="controls">
    <div class="control-group">
      <input type="text" id="ipInput" placeholder="IP (e.g. 192.168.1.100)">
      <button class="btn-block-ip" onclick="blockIP()">🔴 Block IP</button>
      <button class="btn-unblock-ip" onclick="unblockIP()">🔵 Unblock IP</button>
    </div>
  </div>
</div>

<div id="tab-alerts" class="tab-content">
  <div class="section" style="margin-top:10px">
    <div class="section-header">
      <h2>🤖 Smart Agent Alerts</h2>
      <span id="alertCount" style="color:#ff4444">0 alerts</span>
    </div>
    <table>
      <tr>
        <th>Time</th><th>Client IP</th>
        <th>Domain</th><th>Reason</th>
        <th>Severity</th><th>Action</th>
      </tr>
      <tbody id="alertsTable">
        <tr><td colspan="6" style="text-align:center;color:#888">No alerts yet...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div id="tab-logs" class="tab-content">
  <div class="section" style="margin-top:10px">
    <div class="section-header">
      <h2>📋 Live DNS Query Log</h2>
      <span style="color:#888;font-size:12px">Last 100 | Refresh 2s</span>
    </div>
    <table>
      <tr>
        <th>Time</th><th>Domain</th>
        <th>Client IP</th><th>Category</th>
        <th>Action</th>
      </tr>
      <tbody id="logsTable">
        <tr><td colspan="5" style="text-align:center;color:#888">Waiting for queries...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div id="tab-ips" class="tab-content">
  <div class="section" style="margin-top:10px">
    <div class="section-header">
      <h2>🚫 Blocked IPs</h2>
      <span id="ipCount" style="color:#ff0066">0 blocked</span>
    </div>
    <table>
      <tr>
        <th>IP Address</th><th>Reason</th><th>Action</th>
      </tr>
      <tbody id="ipsTable">
        <tr><td colspan="3" style="text-align:center;color:#888">No blocked IPs...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div id="tab-devices" class="tab-content">
  <div class="section" style="margin-top:10px">
    <div class="section-header">
      <h2>💻 Connected Devices</h2>
      <span id="deviceCount" style="color:#00d4ff">0 devices</span>
    </div>
    <table>
      <tr>
        <th>Device ID</th><th>Student ID</th>
        <th>OS</th><th>Browser</th>
        <th>IP</th><th>Last Seen</th>
        <th>Status</th>
      </tr>
      <tbody id="devicesTable">
        <tr><td colspan="7" style="text-align:center;color:#888">No devices connected...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<div id="tab-reports" class="tab-content">
  <div class="section" style="margin-top:10px">
    <div class="section-header">
      <h2>🧠 Client Agent Reports</h2>
      <span id="reportCount" style="color:#ff00ff">0 reports</span>
    </div>
    <table>
      <tr>
        <th>Time</th><th>Device</th>
        <th>Student</th><th>Domain</th>
        <th>Alert Type</th><th>Keyword</th>
        <th>Severity</th>
      </tr>
      <tbody id="reportsTable">
        <tr><td colspan="7" style="text-align:center;color:#888">No reports yet...</td></tr>
      </tbody>
    </table>
  </div>
</div>

<script>
function showTab(name,el){
  document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');});
  document.querySelectorAll('.tab-content').forEach(function(t){t.classList.remove('active');});
  el.classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
}
function updateStats(){
  fetch('/api/stats')
    .then(function(r){return r.json();})
    .then(function(d){
      document.getElementById('total').textContent=d.total_queries;
      document.getElementById('blocked').textContent=d.blocked_queries;
      document.getElementById('allowed').textContent=d.allowed_queries;
      document.getElementById('clients').textContent=d.active_clients;
      document.getElementById('blockedips').textContent=d.blocked_ips;
    })
    .catch(function(){
      document.getElementById('serverStatus').textContent='● OFFLINE';
      document.getElementById('serverStatus').style.background='#ff4444';
    });
}
function updateLogs(){
  fetch('/api/logs')
    .then(function(r){return r.json();})
    .then(function(data){
      if(!data||!data.length)return;
      var tbody=document.getElementById('logsTable');
      tbody.innerHTML='';
      data.slice().reverse().forEach(function(log){
        var row=document.createElement('tr');
        var time=log.timestamp.split('T')[1].split('+')[0].split('Z')[0];
        row.innerHTML='<td>'+time+'</td><td>'+log.domain+'</td><td>'+log.client_ip+'</td><td>'+log.category+'</td><td class="'+(log.blocked?'blocked':'allowed')+'">'+(log.blocked?'🚫 BLOCKED':'✅ ALLOWED')+'</td>';
        tbody.appendChild(row);
      });
    });
}
function updateAlerts(){
  fetch('/api/alerts')
    .then(function(r){return r.json();})
    .then(function(data){
      if(!data||!data.length)return;
      document.getElementById('alertCount').textContent=data.length+' alerts';
      var tbody=document.getElementById('alertsTable');
      tbody.innerHTML='';
      data.slice().reverse().forEach(function(a){
        var row=document.createElement('tr');
        var time=a.timestamp.split('T')[1].split('+')[0].split('Z')[0];
        var isMental=a.reason.indexOf('mental')!==-1||a.reason.indexOf('Mental')!==-1;
        if(isMental)row.className='alert-mental';
        row.innerHTML='<td>'+time+'</td><td>'+a.client_ip+'</td><td>'+a.domain+'</td><td>'+a.reason+'</td><td class="'+(isMental?'mental':a.severity)+'">'+a.severity.toUpperCase()+'</td><td><button class="btn-block-ip" style="padding:3px 8px;font-size:11px" onclick="blockIPDirect(\''+a.client_ip+'\')">Block</button></td>';
        tbody.appendChild(row);
      });
    });
}
function updateBlockedIPs(){
  fetch('/api/blocked-ips')
    .then(function(r){return r.json();})
    .then(function(data){
      if(!data)return;
      document.getElementById('ipCount').textContent=data.length+' blocked';
      var tbody=document.getElementById('ipsTable');
      if(!data.length){tbody.innerHTML='<tr><td colspan="3" style="text-align:center;color:#888">No blocked IPs</td></tr>';return;}
      tbody.innerHTML='';
      data.forEach(function(ip){
        var row=document.createElement('tr');
        row.innerHTML='<td>'+ip+'</td><td>Auto/Manual blocked</td><td><button class="btn-unblock-ip" style="padding:3px 8px;font-size:11px" onclick="unblockIPDirect(\''+ip+'\')">Unblock</button></td>';
        tbody.appendChild(row);
      });
    });
}
function updateDevices(){
  fetch('/api/devices')
    .then(function(r){return r.json();})
    .then(function(data){
      if(!data)return;
      document.getElementById('deviceCount').textContent=data.length+' devices';
      var tbody=document.getElementById('devicesTable');
      if(!data.length){tbody.innerHTML='<tr><td colspan="7" style="text-align:center;color:#888">No devices connected...</td></tr>';return;}
      tbody.innerHTML='';
      data.forEach(function(d){
        var row=document.createElement('tr');
        var lastSeen=d.last_seen?new Date(d.last_seen).toLocaleTimeString():'unknown';
        row.innerHTML='<td>'+d.device_id+'</td><td>'+d.student_id+'</td><td>'+d.os+'</td><td>'+d.browser+'</td><td>'+d.ip+'</td><td>'+lastSeen+'</td><td class="'+(d.online?'device-online':'device-offline')+'">'+(d.online?'● ONLINE':'○ OFFLINE')+'</td>';
        tbody.appendChild(row);
      });
    });
}
function updateReports(){
  fetch('/api/client-reports')
    .then(function(r){return r.json();})
    .then(function(data){
      if(!data||!data.length)return;
      document.getElementById('reportCount').textContent=data.length+' reports';
      var tbody=document.getElementById('reportsTable');
      tbody.innerHTML='';
      data.slice().reverse().forEach(function(r){
        var row=document.createElement('tr');
        var time=r.timestamp?r.timestamp.split('T')[1].split('+')[0].split('Z')[0]:'';
        var isMental=r.alert_type==='mental_health';
        if(isMental)row.className='alert-mental';
        row.innerHTML='<td>'+time+'</td><td>'+r.device_id+'</td><td>'+r.student_id+'</td><td>'+r.domain+'</td><td class="'+(isMental?'mental':'')+'">'+r.alert_type+'</td><td>'+r.keyword+'</td><td class="'+r.severity+'">'+r.severity.toUpperCase()+'</td>';
        tbody.appendChild(row);
      });
    });
}
function blockDomain(){
  var d=document.getElementById('domainInput').value.trim();
  if(!d){alert('Enter a domain!');return;}
  fetch('/api/block?domain='+d).then(function(r){return r.json();}).then(function(data){alert('✅ '+data.message);document.getElementById('domainInput').value='';});
}
function unblockDomain(){
  var d=document.getElementById('domainInput').value.trim();
  if(!d){alert('Enter a domain!');return;}
  fetch('/api/unblock?domain='+d).then(function(r){return r.json();}).then(function(data){alert('✅ '+data.message);document.getElementById('domainInput').value='';});
}
function blockIP(){
  var ip=document.getElementById('ipInput').value.trim();
  if(!ip){alert('Enter an IP!');return;}
  blockIPDirect(ip);
  document.getElementById('ipInput').value='';
}
function unblockIP(){
  var ip=document.getElementById('ipInput').value.trim();
  if(!ip){alert('Enter an IP!');return;}
  unblockIPDirect(ip);
  document.getElementById('ipInput').value='';
}
function blockIPDirect(ip){
  fetch('/api/block-ip?ip='+ip).then(function(r){return r.json();}).then(function(data){alert('🔴 '+data.message);updateBlockedIPs();});
}
function unblockIPDirect(ip){
  fetch('/api/unblock-ip?ip='+ip).then(function(r){return r.json();}).then(function(data){alert('🔵 '+data.message);updateBlockedIPs();});
}
setInterval(function(){
  updateStats();updateLogs();
  updateAlerts();updateBlockedIPs();
  updateDevices();updateReports();
},2000);
updateStats();updateLogs();
updateAlerts();updateBlockedIPs();
updateDevices();updateReports();
</script>
</body>
</html>`

func cleanupActiveIPs() {
	for {
		time.Sleep(5 * time.Minute)
		mu.Lock()
		for ip, lastSeen := range activeIPs {
			if time.Since(lastSeen) >
				10*time.Minute {
				delete(activeIPs, ip)
			}
		}
		mu.Unlock()
	}
}

func cleanupOldLogs() {
	for {
		time.Sleep(1 * time.Hour)
		mu.Lock()
		if len(queryLogs) > 1000 {
			queryLogs =
				queryLogs[len(queryLogs)-1000:]
		}
		if len(agentAlerts) > 500 {
			agentAlerts =
				agentAlerts[len(agentAlerts)-500:]
		}
		if len(clientReports) > 1000 {
			clientReports =
				clientReports[
					len(clientReports)-1000:]
		}
		for ip := range recentBlocks {
			if _, active := activeIPs[ip];
				!active {
				delete(recentBlocks, ip)
			}
		}
		mu.Unlock()
	}
}

func runConsole() {
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Println("[CONSOLE] Commands:")
	fmt.Println("  block <domain>")
	fmt.Println("  unblock <domain>")
	fmt.Println("  blockip <ip>")
	fmt.Println("  unblockip <ip>")
	fmt.Println("  stats")
	fmt.Println("  quit")

	for scanner.Scan() {
		line := strings.TrimSpace(
			scanner.Text())
		parts := strings.SplitN(line, " ", 2)
		cmd := parts[0]
		arg := ""
		if len(parts) > 1 {
			arg = strings.TrimSpace(parts[1])
		}
		switch cmd {
		case "block":
			if arg == "" {
				fmt.Println("Usage: block <domain>")
				continue
			}
			mu.Lock()
			blockedDomains[arg] = true
			mu.Unlock()
			saveAllData()
			fmt.Printf("[CONSOLE] Blocked: %s\n",
				arg)
		case "unblock":
			if arg == "" {
				fmt.Println(
					"Usage: unblock <domain>")
				continue
			}
			mu.Lock()
			delete(blockedDomains, arg)
			mu.Unlock()
			saveAllData()
			fmt.Printf(
				"[CONSOLE] Unblocked: %s\n", arg)
		case "blockip":
			if arg == "" {
				fmt.Println("Usage: blockip <ip>")
				continue
			}
			mu.Lock()
			blockedIPs[arg] = true
			mu.Unlock()
			saveAllData()
			fmt.Printf(
				"[CONSOLE] Blocked IP: %s\n", arg)
		case "unblockip":
			if arg == "" {
				fmt.Println(
					"Usage: unblockip <ip>")
				continue
			}
			mu.Lock()
			delete(blockedIPs, arg)
			mu.Unlock()
			saveAllData()
			fmt.Printf(
				"[CONSOLE] Unblocked IP: %s\n",
				arg)
		case "stats":
			mu.Lock()
			fmt.Printf(
				"[STATS] Total:%d Blocked:%d "+
					"Allowed:%d BlockedIPs:%d "+
					"Devices:%d\n",
				stats.TotalQueries,
				stats.BlockedQueries,
				stats.AllowedQueries,
				len(blockedIPs),
				len(deviceRegistry))
			mu.Unlock()
		case "quit":
			fmt.Println(
				"[CONSOLE] Saving and exiting...")
			saveAllData()
			os.Exit(0)
		default:
			if cmd != "" {
				fmt.Printf(
					"[CONSOLE] Unknown: %s\n", cmd)
			}
		}
	}
}

func printBanner() {
	fmt.Println(
		"╔══════════════════════════════════════╗")
	fmt.Println(
		"║  AeroShield DNS v4 + Client Agent   ║")
	fmt.Println(
		"║  Server + Client Side Protection    ║")
	fmt.Println(
		"╚══════════════════════════════════════╝")
	fmt.Println("")
	fmt.Printf("Host      : %s\n", SERVER_HOST)
	fmt.Printf("IP        : %s\n", SERVER_IP)
	fmt.Printf("HTTP Port : %s\n", HTTP_PORT)
	fmt.Printf("DNS Port  : %s\n", DNS_PORT)
	fmt.Printf("OTG Key   : %s...\n",
		OTG_KEY[:8])
	fmt.Printf("CatDNS ID : %s\n",
		WEBTITAN_CATID)
	fmt.Printf("CF Proxy  : %s\n",
		CLOUDFLARE_PROXY)
	fmt.Println("")
	fmt.Println("Server Routes:")
	fmt.Printf("  Dashboard     : https://%s/\n",
		SERVER_HOST)
	fmt.Printf("  PAC File      : https://%s/proxy.pac\n",
		SERVER_HOST)
	fmt.Printf("  Block Page    : https://%s/blocked\n",
		SERVER_HOST)
	fmt.Printf("  Client Rules  : https://%s/api/client-rules\n",
		SERVER_HOST)
	fmt.Printf("  Client Report : https://%s/api/client-report\n",
		SERVER_HOST)
	fmt.Printf("  Devices       : https://%s/api/devices\n",
		SERVER_HOST)
	fmt.Println("")
}

func main() {
	printBanner()

	log.Println("[STARTUP] Loading data...")
	loadAllData()

	mu.Lock()
	for k, v := range defaultBlockedDomains {
		if _, exists :=
			blockedDomains[k]; !exists {
			blockedDomains[k] = v
		}
	}
	for k, v := range defaultAllowedDomains {
		if _, exists :=
			allowedDomains[k]; !exists {
			allowedDomains[k] = v
		}
	}
	mu.Unlock()

	log.Printf("[STARTUP] %d blocked domains",
		len(blockedDomains))
	log.Printf("[STARTUP] %d allowed domains",
		len(allowedDomains))
	log.Printf("[STARTUP] %d blocked IPs",
		len(blockedIPs))

	go cleanupActiveIPs()
	go cleanupOldLogs()
	go autoSave()

	mux := http.NewServeMux()

	mux.HandleFunc("/",
		basicAuth(handleDashboard))
	mux.HandleFunc("/proxy.pac", handlePAC)
	mux.HandleFunc("/wpad.dat", handlePAC)
	mux.HandleFunc("/wpad.da", handlePAC)
	mux.HandleFunc("/blocked", handleBlockPage)
	mux.HandleFunc("/redirect",
		handleBlockRedirect)

	mux.HandleFunc("/api/stats",
		basicAuth(handleStats))
	mux.HandleFunc("/api/logs",
		basicAuth(handleLogs))
	mux.HandleFunc("/api/alerts",
		basicAuth(handleAlerts))
	mux.HandleFunc("/api/blocked-ips",
		basicAuth(handleBlockedIPs))
	mux.HandleFunc("/api/block",
		basicAuth(handleBlock))
	mux.HandleFunc("/api/unblock",
		basicAuth(handleUnblock))
	mux.HandleFunc("/api/block-ip",
		basicAuth(handleBlockIP))
	mux.HandleFunc("/api/unblock-ip",
		basicAuth(handleUnblockIP))
	mux.HandleFunc("/api/client-report",
		handleClientReport)
	mux.HandleFunc("/api/client-rules",
		handleClientRules)
	mux.HandleFunc("/api/client-reports",
		basicAuth(handleClientReports))
	mux.HandleFunc("/api/devices",
		basicAuth(handleDevices))

	udpServer := &dns.Server{
		Addr:    DNS_PORT,
		Net:     "udp",
		Handler: dns.HandlerFunc(handleDNS),
	}
	tcpServer := &dns.Server{
		Addr:    DNS_PORT,
		Net:     "tcp",
		Handler: dns.HandlerFunc(handleDNS),
	}

	go func() {
		log.Printf("[DNS] UDP on %s", DNS_PORT)
		if err :=
			udpServer.ListenAndServe();
			err != nil {
			log.Printf("[DNS] UDP error: %v",
				err)
		}
	}()

	go func() {
		log.Printf("[DNS] TCP on %s", DNS_PORT)
		if err :=
			tcpServer.ListenAndServe();
			err != nil {
			log.Printf("[DNS] TCP error: %v",
				err)
		}
	}()

	go runConsole()

	log.Println("")
	log.Println(
		"╔══════════════════════════════════════╗")
	log.Println(
		"║    AeroShield DNS v4 is LIVE!       ║")
	log.Println(
		"╚══════════════════════════════════════╝")
	log.Printf("🌐 https://%s/", SERVER_HOST)
	log.Printf("📄 https://%s/proxy.pac",
		SERVER_HOST)
	log.Printf("🚫 https://%s/blocked",
		SERVER_HOST)
	log.Printf("🔌 https://%s/api/client-rules",
		SERVER_HOST)
	log.Printf("📡 DNS: %s:53", SERVER_IP)
	log.Println("")

	if err := http.ListenAndServe(
		HTTP_PORT, mux); err != nil {
		log.Fatal("[HTTP] Error:", err)
		os.Exit(1)
	}
}



