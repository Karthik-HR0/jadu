package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
)

var (
    thread       *int
    silent       *bool
    ua           *string
    rc           *string
    detailed     *bool
    sensitive    *bool
    showPatterns *bool
    updateCheck  *bool
    secrets      map[string]bool = make(map[string]bool)
    secretsMu    sync.Mutex      // Add this mutex to synchronize access
    extrapattern *string
    currentVersion string = "1.0"
)
type SecretPattern struct {
	Pattern *regexp.Regexp
	Label   string
}

type GithubRelease struct {
	TagName string `json:"tag_name"`
}

var secretsPatterns = []SecretPattern{

	          {Pattern: regexp.MustCompile(`Basic [A-Za-z0-9+/]{15}`), Label: "Basic Auth Credential"},
	{Pattern: regexp.MustCompile(`(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`), Label: "Slack Token"},
	{Pattern: regexp.MustCompile(`https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`), Label: "Slack Webhook URL"},
	{Pattern: regexp.MustCompile(`[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].{0,30}['\"\\s][0-9a-f]{32}['\"\\s]`), Label: "Facebook Access Token"},
	{Pattern: regexp.MustCompile(`[t|T][w|W][i|I][t|T][t|T][e|E][r|R].{0,30}['\"\\s][0-9a-zA-Z]{35,44}['\"\\s]`), Label: "Twitter Access Token"},
	{Pattern: regexp.MustCompile(`[h|H][e|E][r|R][o|O][k|K][u|U].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`), Label: "Heroku API Key"},
	{Pattern: regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), Label: "Generic API Key"},
	{Pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), Label: "Stripe Test Key"},
	{Pattern: regexp.MustCompile(`sk_live_[0-9a-z]{32}`), Label: "Stripe Live Secret Key"},
	{Pattern: regexp.MustCompile(`[0-9(+-[0-9A-Za-z_]{32}.apps.qooqleusercontent.com`), Label: "Google App Content Token"}, // Likely a typo in original ("qooqle"), kept as-is
	{Pattern: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`), Label: "Google API Key"},
	{Pattern: regexp.MustCompile(`6L[0-9A-Za-z-_]{38}`), Label: "Google reCAPTCHA Key"},
	{Pattern: regexp.MustCompile(`ya29\\.[0-9A-Za-z\\-_]+`), Label: "Google OAuth Token"},
	{Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Label: "AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), Label: "Amazon MWS Auth Token"},
	{Pattern: regexp.MustCompile(`s3\\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\\.s3\\.amazonaws.com`), Label: "AWS S3 Bucket URL"},
	{Pattern: regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`), Label: "Facebook App Token"},
	{Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Label: "SendGrid API Key"},
	{Pattern: regexp.MustCompile(`AC[a-zA-Z0-9_\\-]{32}`), Label: "Twilio Account SID"},
	{Pattern: regexp.MustCompile(`AP[a-zA-Z0-9_\\-]{32}`), Label: "Twilio API Key"},
	{Pattern: regexp.MustCompile(`access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}`), Label: "Square Access Token"},
	{Pattern: regexp.MustCompile(`sq0csp-[ 0-9A-Za-z\\-_]{43}`), Label: "Square Client Secret"},
	{Pattern: regexp.MustCompile(`sqOatp-[0-9A-Za-z\\-_]{22}`), Label: "Square OAuth Token"},
	{Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`), Label: "Stripe Live Key"},
	{Pattern: regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`), Label: "Stripe Restricted Key"},
	{Pattern: regexp.MustCompile(`[a-zA-Z0-9_-]*:[a-zA-Z0-9_\\-]+@github\\.com*`), Label: "GitHub SSH Credential"},
	{Pattern: regexp.MustCompile(`-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY-----`), Label: "Generic Private Key"},
	{Pattern: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----`), Label: "RSA Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?zopim[_-]?account[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Zopim Account Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?zhuliang[_-]?gh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Zhuliang GitHub Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?zensonatypepassword[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Zen Sonatype Password"},
	{Pattern: regexp.MustCompile(`(?i)zendesk(_api_token|_key|_token|-travis-github|_url|_username)(\\s|=)`), Label: "Zendesk Credential"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?yt[_-]?server[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "YouTube Server API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?yt[_-]?partner[_-]?refresh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "YouTube Partner Refresh Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?yt[_-]?partner[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "YouTube Partner Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?yt[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "YouTube Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?yt[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "YouTube API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?yt[_-]?account[_-]?refresh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "YouTube Account Refresh Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?yt[_-]?account[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "YouTube Account Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?yangshun[_-]?gh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Yangshun GitHub Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?yangshun[_-]?gh[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Yangshun GitHub Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?www[_-]?googleapis[_-]?com[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google APIs URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wpt[_-]?ssh[_-]?private[_-]?key[_-]?base64[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WPT SSH Private Key (Base64)"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wpt[_-]?ssh[_-]?connect[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WPT SSH Connect String"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wpt[_-]?report[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WPT Report API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wpt[_-]?prepare[_-]?dir[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WPT Prepare Directory"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wpt[_-]?db[_-]?user[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WPT Database User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wpt[_-]?db[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WPT Database Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wporg[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WordPress.org Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wpjm[_-]?phpunit[_-]?google[_-]?geocode[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WPJM PHPUnit Google Geocode API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wordpress[_-]?db[_-]?user[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WordPress Database User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wordpress[_-]?db[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WordPress Database Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wincert[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WinCert Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?widget[_-]?test[_-]?server[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Widget Test Server"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?widget[_-]?fb[_-]?password[_-]?3[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Widget Facebook Password 3"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?widget[_-]?fb[_-]?password[_-]?2[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Widget Facebook Password 2"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?widget[_-]?fb[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Widget Facebook Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?widget[_-]?basic[_-]?password[_-]?5[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Widget Basic Password 5"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?widget[_-]?basic[_-]?password[_-]?4[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Widget Basic Password 4"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?widget[_-]?basic[_-]?password[_-]?3[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Widget Basic Password 3"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?widget[_-]?basic[_-]?password[_-]?2[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Widget Basic Password 2"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?widget[_-]?basic[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Widget Basic Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?watson[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Watson Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?watson[_-]?device[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Watson Device Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?watson[_-]?conversation[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Watson Conversation Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?wakatime[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WakaTime API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?vscetoken[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "VSCE Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?visual[_-]?recognition[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Visual Recognition API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?virustotal[_-]?apikey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "VirusTotal API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?vip[_-]?github[_-]?deploy[_-]?key[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "VIP GitHub Deploy Key Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?vip[_-]?github[_-]?deploy[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "VIP GitHub Deploy Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?vip[_-]?github[_-]?build[_-]?repo[_-]?deploy[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "VIP GitHub Build Repo Deploy Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?v[_-]?sfdc[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Salesforce Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?v[_-]?sfdc[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Salesforce Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?usertravis[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?user[_-]?assets[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "User Assets Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?user[_-]?assets[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "User Assets Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?use[_-]?ssh[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SSH Usage Flag"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?us[_-]?east[_-]?1[_-]?elb[_-]?amazonaws[_-]?com[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS US-East-1 ELB URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?urban[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Urban Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?urban[_-]?master[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Urban Master Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?urban[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Urban Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?unity[_-]?serial[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Unity Serial"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?unity[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Unity Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twitteroauthaccesstoken[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twitter OAuth Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twitteroauthaccesssecret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twitter OAuth Access Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twitter[_-]?consumer[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twitter Consumer Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twitter[_-]?consumer[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twitter Consumer Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twine[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twine Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twilio[_-]?token[\"']?[^\\S Rundown]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twilio Auth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twilio[_-]?sid[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twilio SID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twilio[_-]?configuration[_-]?sid[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twilio Configuration SID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twilio[_-]?chat[_-]?account[_-]?api[_-]?service[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twilio Chat API Service"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twilio[_-]?api[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twilio API Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twilio[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twilio API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?trex[_-]?okta[_-]?client[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "TRex Okta Client Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?trex[_-]?client[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "TRex Client Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?travis[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis CI Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?travis[_-]?secure[_-]?env[_-]?vars[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis Secure Env Vars"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?travis[_-]?pull[_-]?request[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis Pull Request"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?travis[_-]?gh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis GitHub Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?travis[_-]?e2e[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis E2E Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?travis[_-]?com[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis.com Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?travis[_-]?branch[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis Branch"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?travis[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?travis[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?token[_-]?core[_-]?java[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Core Java Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?thera[_-]?oss[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Thera OSS Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?tester[_-]?keys[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Tester Keys Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?test[_-]?test[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Test Credential"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?test[_-]?github[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Test GitHub Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?tesco[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Tesco API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?svn[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SVN Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?surge[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Surge Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?surge[_-]?login[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Surge Login"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?stripe[_-]?public[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Stripe Public Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?stripe[_-]?private[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Stripe Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?strip[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Stripe Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?strip[_-]?publishable[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Stripe Publishable Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?stormpath[_-]?api[_-]?key[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Stormpath API Key Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?stormpath[_-]?api[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Stormpath API Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?starship[_-]?auth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Starship Auth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?starship[_-]?account[_-]?sid[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Starship Account SID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?star[_-]?test[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Star Test Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?star[_-]?test[_-]?location[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Star Test Location"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?star[_-]?test[_-]?bucket[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Star Test Bucket"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?star[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Star Test AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?staging[_-]?base[_-]?url[_-]?runscope[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Staging Runscope Base URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ssmtp[_-]?config[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SSMTP Config"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sshpass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SSH Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?srcclr[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SourceClear API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?square[_-]?reader[_-]?sdk[_-]?repository[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Square Reader SDK Repository Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sqssecretkey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS SQS Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sqsaccesskey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS SQS Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?spring[_-]?mail[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Spring Mail Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?spotify[_-]?api[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Spotify API Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?spotify[_-]?api[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Spotify API Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?spaces[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DigitalOcean Spaces Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?spaces[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DigitalOcean Spaces Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?soundcloud[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SoundCloud Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?soundcloud[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SoundCloud Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatypepassword[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?token[_-]?user[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype Token User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?token[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype Token Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype Pass"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?nexus[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype Nexus Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?gpg[_-]?passphrase[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype GPG Passphrase"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?gpg[_-]?key[_-]?name[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype GPG Key Name"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonar[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SonarQube Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonar[_-]?project[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SonarQube Project Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonar[_-]?organization[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SonarQube Organization Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?socrata[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Socrata Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?socrata[_-]?app[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Socrata App Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?snyk[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Snyk Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?snyk[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Snyk API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?snoowrap[_-]?refresh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Snoowrap Refresh Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?snoowrap[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Snoowrap Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?snoowrap[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Snoowrap Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?slate[_-]?user[_-]?email[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Slate User Email"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?slash[_-]?developer[_-]?space[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Slash Developer Space Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?slash[_-]?developer[_-]?space[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Slash Developer Space"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?signing[_-]?key[_-]?sid[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Signing Key SID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?signing[_-]?key[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Signing Key Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?signing[_-]?key[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Signing Key Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?signing[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Signing Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?setsecretkey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Set Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?setdstsecretkey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Set DST Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?setdstaccesskey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Set DST Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ses[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS SES Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ses[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS SES Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?service[_-]?account[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Service Account Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sentry[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sentry Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sentry[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sentry Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sentry[_-]?endpoint[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sentry Endpoint"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sentry[_-]?default[_-]?org[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sentry Default Org"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sentry[_-]?auth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sentry Auth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sendwithus[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SendWithUs Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sendgrid[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SendGrid Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sendgrid[_-]?user[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SendGrid User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sendgrid[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SendGrid Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sendgrid[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SendGrid Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sendgrid[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SendGrid API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sendgrid[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SendGrid Generic Credential"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?selion[_-]?selenium[_-]?host[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Selion Selenium Host"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?selion[_-]?log[_-]?level[_-]?dev[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Selion Log Level Dev"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?segment[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Segment API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secretkey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Generic Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secretaccesskey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Generic Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?key[_-]?base[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret Key Base"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?9[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 9"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?8[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 8"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?7[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 7"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?6[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 6"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?5[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 5"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?4[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 4"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?3[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 3"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?2[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 2"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?11[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 11"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?10[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 10"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?1[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 1"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?0[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret 0"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sdr[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "SDR Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?scrutinizer[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Scrutinizer Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sauce[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sauce Labs Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sandbox[_-]?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sandbox AWS Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sandbox[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sandbox AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sandbox[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sandbox Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?salesforce[_-]?bulk[_-]?test[_-]?security[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Salesforce Bulk Test Security Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?salesforce[_-]?bulk[_-]?test[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Salesforce Bulk Test Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sacloud[_-]?api[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sakura Cloud API"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sacloud[_-]?access[_-]?token[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sakura Cloud Access Token Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sacloud[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sakura Cloud Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?user[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 User Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?secret[_-]?assets[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Secret Assets"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?secret[_-]?app[_-]?logs[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Secret App Logs"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?key[_-]?assets[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Key Assets"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?key[_-]?app[_-]?logs[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Key App Logs"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?external[_-]?3[_-]?amazonaws[_-]?com[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 External Amazon AWS URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?bucket[_-]?name[_-]?assets[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Bucket Name Assets"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?bucket[_-]?name[_-]?app[_-]?logs[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Bucket Name App Logs"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?s3[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "S3 Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?rubygems[_-]?auth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "RubyGems Auth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?rtd[_-]?store[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "RTD Store Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?rtd[_-]?key[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "RTD Key Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?route53[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Route53 Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ropsten[_-]?private[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Ropsten Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?rinkeby[_-]?private[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Rinkeby Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?rest[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "REST API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?repotoken[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Repository Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?reporting[_-]?webdav[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Reporting WebDAV URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?reporting[_-]?webdav[_-]?pwd[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Reporting WebDAV Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?release[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Release Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?release[_-]?gh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Release GitHub Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?registry[_-]?secure[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Registry Secure"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?registry[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Registry Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?refresh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Refresh Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?rediscloud[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Redis Cloud URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?redis[_-]?stunnel[_-]?urls[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Redis STunnel URLs"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?randrmusicapiaccesstoken[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "R&R Music API Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?rabbitmq[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "RabbitMQ Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?quip[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Quip Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?qiita[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Qiita Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?pypi[_-]?passowrd[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "PyPI Password"}, // Typo "passowrd" kept from original
	{Pattern: regexp.MustCompile(`(?i)[\"']?pushover[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Pushover Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?publish[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Publish Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?publish[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Publish Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?publish[_-]?access[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Publish Access"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?project[_-]?config[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Project Config"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?prod[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Production Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?prod[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Production Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?prod[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Production Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?private[_-]?signing[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Private Signing Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?pring[_-]?mail[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Spring Mail Username"}, // Likely typo "pring" from "spring"
	{Pattern: regexp.MustCompile(`(?i)[\"']?preferred[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Preferred Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?prebuild[_-]?auth[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Prebuild Auth"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?postgresql[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "PostgreSQL Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?postgresql[_-]?db[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "PostgreSQL Database"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?postgres[_-]?env[_-]?postgres[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Postgres Env Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?postgres[_-]?env[_-]?postgres[_-]?db[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Postgres Env Database"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?plugin[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Plugin Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?plotly[_-]?apikey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Plotly API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?places[_-]?apikey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Places API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?places[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Places API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?pg[_-]?host[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "PostgreSQL Host"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?pg[_-]?database[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "PostgreSQL Database Name"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?personal[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Personal Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?personal[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Personal Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?percy[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Percy Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?percy[_-]?project[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Percy Project"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?paypal[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "PayPal Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?passwordtravis[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Travis Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?parse[_-]?js[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Parse JS Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?pagerduty[_-]?apikey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "PagerDuty API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?packagecloud[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "PackageCloud Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ossrh[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OSSRH Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ossrh[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OSSRH Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ossrh[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OSSRH Password"},
       	{Pattern: regexp.MustCompile(`(?i)[\"']?ossrh[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OSSRH Pass"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ossrh[_-]?jira[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OSSRH Jira Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?os[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OS Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?os[_-]?auth[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OS Auth URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?org[_-]?project[_-]?gradle[_-]?sonatype[_-]?nexus[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Org Project Gradle Sonatype Nexus Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?org[_-]?gradle[_-]?jvmargs[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Org Gradle JVM Args"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?openwhisk[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OpenWhisk Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?open[_-]?test[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Open Test Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?open[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Open Test AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?onesignal[_-]?user[_-]?auth[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OneSignal User Auth Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?onesignal[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OneSignal API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?omise[_-]?pubkey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Omise Public Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?omise[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Omise Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?okta[_-]?oauth2[_-]?clientsecret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Okta OAuth2 Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?okta[_-]?oauth2[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Okta OAuth2 Client Secret Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?okta[_-]?client[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Okta Client Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?oftch[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OFTCH Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?octest[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Octest Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?octest[_-]?app[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Octest App Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?octest[_-]?app[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Octest App Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?oc[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OC Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?object[_-]?store[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Object Store Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?object[_-]?store[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Object Store Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?object[_-]?store[_-]?bucket[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Object Store Bucket"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?npm[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "NPM Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?npm[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "NPM Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?npm[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "NPM Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?npm[_-]?email[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "NPM Email"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?npm[_-]?auth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "NPM Auth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?npm[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "NPM API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?npm[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "NPM API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?now[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Now Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?non[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Non Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?node[_-]?pre[_-]?gyp[_-]?secretaccesskey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Node Pre-Gyp Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?node[_-]?pre[_-]?gyp[_-]?accesskeyid[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Node Pre-Gyp Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?node[_-]?env[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Node Environment"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?nexuspassword[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Nexus Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?nexus[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Nexus Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?nexus[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Nexus Password Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?new[_-]?relic[_-]?license[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "New Relic License Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?netlify[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Netlify API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mysqlsecret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MySQL Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mysqlmasteruser[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MySQL Master User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mysql[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MySQL Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mysql[_-]?root[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MySQL Root Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mysql[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MySQL Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mysql[_-]?hostname[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MySQL Hostname"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mysql[_-]?database[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MySQL Database"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?my[_-]?secret[_-]?env[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "My Secret Env"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?multi[_-]?workflow[_-]?ossrh[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Multi Workflow OSSRH Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?multi[_-]?workflow[_-]?ossrh[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Multi Workflow OSSRH Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?multi[_-]?test[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Multi Test"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?multi[_-]?soft[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Multi Soft Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?multi[_-]?soft[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Multi Soft AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?multi[_-]?connect[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Multi Connect Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?multi[_-]?connect[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Multi Connect AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?multi[_-]?bio[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Multi Bio Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?multi[_-]?bio[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Multi Bio AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mongolab[_-]?uri[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MongoLab URI"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mongolab[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MongoLab API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mongo[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MongoDB Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mongo[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MongoDB Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mongo[_-]?host[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MongoDB Host"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mongo[_-]?database[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MongoDB Database"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mixpanel[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mixpanel Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mixpanel[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mixpanel API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mixpanel[_-]?api[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mixpanel API Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mg[_-]?public[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun Public API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mg[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mg[_-]?api[_-]?base[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun API Base URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?metrictank[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MetricTank Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?maven[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Maven Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?maven[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Maven Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?maven[_-]?master[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Maven Master Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mapboxaccesstoken[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mapbox Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mapbox[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mapbox API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mapbox[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mapbox Access Token Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?manifest[_-]?s3[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Manifest S3 Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?manifest[_-]?s3[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Manifest S3 Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?manifest[_-]?app[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Manifest App Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?manifest[_-]?app[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Manifest App Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mandrill[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mandrill API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?management[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Management Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?management[_-]?keys[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Management Keys"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?manage[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Manage Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?manage[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Manage Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?manage[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Manage AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?magento[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Magento Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?magento[_-]?auth[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Magento Auth Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?magento[_-]?auth[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Magento Auth Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mailgun[_-]?secret[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun Secret API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mailgun[_-]?pub[_-]?apikey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun Public API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mailgun[_-]?pub[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun Public API Key Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mailgun[_-]?priv[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun Private API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mailgun[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mailgun[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mailgun[_-]?api[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailgun API"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mailchimp[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailchimp Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mailchimp[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mailchimp API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mail[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mail Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mail[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Mail Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?magical[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Magical API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ls[_-]?access[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "LS Access ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ls[_-]?access[_-]?data[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "LS Access Data"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?logzio[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Logz.io Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?loggly[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Loggly Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?localhost[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Localhost Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?localhost[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Localhost Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ll[_-]?publish[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "LL Publish URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?live[_-]?test[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Live Test Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?live[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Live Test AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?linkedin[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "LinkedIn Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?lgtm[_-]?github[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "LGTM GitHub Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?lc[_-]?ctype[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "LC CType"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?lc[_-]?all[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "LC All"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?lang[_-]?python3[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Lang Python3"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?kovan[_-]?private[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Kovan Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?keystore[_-]?pass[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Keystore Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?keycloak[_-]?test[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Keycloak Test Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?keycloak[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Keycloak Test AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?keycloak[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Keycloak Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?key[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Key Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?jwt[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "JWT Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?jdbc[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "JDBC URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?jdbc[_-]?databaseurl[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "JDBC Database URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?itly[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Itly API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ios[_-]?cookie[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "iOS Cookie"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?internal[_-]?slack[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Internal Slack URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?integration[_-]?test[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Integration Test Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?integration[_-]?test[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Integration Test AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?integration[_-]?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Integration AWS Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?integration[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Integration AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?incoming[_-]?webhook[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Incoming Webhook URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?imagekit[_-]?private[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "ImageKit Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?hub[_-]?docker[_-]?com[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Hub Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?hub[_-]?docker[_-]?com[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Hub Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?homebrew[_-]?github[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Homebrew GitHub API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?hockeyapp[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "HockeyApp Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?heroku[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Heroku Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?heroku[_-]?email[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Heroku Email"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?heroku[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Heroku API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?heroku[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Heroku API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?hapikey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "HubSpot API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?grgit[_-]?user[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Grgit User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?greenkeeper[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Greenkeeper Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gradle[_-]?signing[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Gradle Signing Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gradle[_-]?signing[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Gradle Signing Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gradle[_-]?publish[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Gradle Publish Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gradle[_-]?publish[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Gradle Publish Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gpg[_-]?private[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GPG Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gpg[_-]?passphrase[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GPG Passphrase"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gpg[_-]?ownertrust[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GPG Owner Trust"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gpg[_-]?keyname[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GPG Key Name"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gpg[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GPG Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?googlemaps[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Maps API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?google[_-]?private[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?google[_-]?client[_-]?secret[_-]?2[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Client Secret 2"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?google[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?google[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google API Key Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?google[_-]?account[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Account Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gogs[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Gogs Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gocd[_-]?github[_-]?oauth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GoCD GitHub OAuth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gocd[_-]?github[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GoCD GitHub Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?user[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?token[_-]?travis[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token Travis"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?token[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?token[_-]?private[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token Private"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?token[_-]?bot[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token Bot"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?token[_-]?2[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token 2"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?repo[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Repo Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?release[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Release Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?pwd[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Password Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?oauth[_-]?token[_-]?travis[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub OAuth Token Travis"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?oauth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub OAuth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?oauth[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub OAuth"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?home[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Home Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?deploy[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Deploy Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?deploy[_-]?hmr[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Deploy HMR Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?auth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Auth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?auth[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Auth"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?git[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Git Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?git[_-]?secret[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Git Secret Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?git[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Git Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?git[_-]?credentials[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Git Credentials"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?git[_-]?committer[_-]?name[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Git Committer Name"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?git[_-]?committer[_-]?email[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Git Committer Email"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?git[_-]?author[_-]?name[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Git Author Name"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?git[_-]?author[_-]?email[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Git Author Email"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ghb[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GHB Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?user[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub User Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?token[_-]?travis[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token Travis Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?token[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token Secret Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?token[_-]?private[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token Private Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?token[_-]?bot[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token Bot Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?token[_-]?2[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token 2 Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Token Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?repo[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Repo Token Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?release[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Release Token Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?pwd[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Password Short"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?oauth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub OAuth Token Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Key Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?email[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Email"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?deploy[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Deploy Token Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?deploy[_-]?hmr[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Deploy HMR Token Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?auth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Auth Token Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gh[_-]?auth[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Auth Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcs[_-]?bucket[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Cloud Storage Bucket"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcr[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Container Registry Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcloud[_-]?service[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Cloud Service Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcloud[_-]?project[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Cloud Project"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcloud[_-]?bucket[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Cloud Bucket"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcloud[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Cloud Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcp[_-]?service[_-]?account[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCP Service Account"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcp[_-]?private[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCP Private Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcp[_-]?private[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCP Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcp[_-]?credentials[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCP Credentials"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcp[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCP Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcp[_-]?client[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCP Client ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcp[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCP API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcp[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCP Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcs[_-]?private[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCS Private Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcs[_-]?private[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCS Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcs[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCS Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcs[_-]?client[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCS Client ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcm[_-]?sender[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCM Sender ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcm[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GCM API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?gcalendar[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Google Calendar Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ftp[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "FTP Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ftp[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "FTP Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ftp[_-]?host[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "FTP Host"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ftp[_-]?anonymous[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "FTP Anonymous Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?foursquare[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Foursquare Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?firebase[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Firebase URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?firebase[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Firebase Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?firebase[_-]?service[_-]?account[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Firebase Service Account Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?firebase[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Firebase Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?firebase[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Firebase API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?firebase[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Firebase API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?figma[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Figma Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?figma[_-]?personal[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Figma Personal Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?eureka[_-]?awssecretkey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Eureka AWS Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?envkey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "EnvKey"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?stripe[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env Stripe Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?publishable[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env Publishable Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?heroku[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env Heroku API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?github[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env GitHub Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?github[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env GitHub Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?github[_-]?client[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env GitHub Client ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?circleci[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env CircleCI Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env AWS Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?env[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Env Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?end[_-]?user[_-]?mysql[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "End User MySQL Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?end[_-]?user[_-]?mysql[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "End User MySQL Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?encryption[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Encryption Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?encrypt[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Encrypt Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?encrypt[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Encrypt Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?e2e[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "E2E Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?e2e[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "E2E AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dynamodb[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DynamoDB Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dynamodb[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DynamoDB Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dynamo[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Dynamo Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dynamo[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Dynamo Access Key ID"},
		{Pattern: regexp.MustCompile(`(?i)[\"']?dropbox[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Dropbox Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dropbox[_-]?oauth[_-]?bearer[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Dropbox OAuth Bearer"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dropbox[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Dropbox Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dropbox[_-]?app[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Dropbox App Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dropbox[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Dropbox Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?drone[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Drone Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dockerhub[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DockerHub Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dockerhub[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DockerHub Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?registry[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Registry Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?hub[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Hub Username Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?hub[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Hub Password Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?hub[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Hub Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?config[_-]?json[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Config JSON"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?docker[_-]?auth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Docker Auth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dnsimple[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DNSimple Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dnsimple[_-]?oauth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DNSimple OAuth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?digitalocean[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DigitalOcean Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?digitalocean[_-]?spaces[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DigitalOcean Spaces Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?digitalocean[_-]?spaces[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DigitalOcean Spaces Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?digitalocean[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DigitalOcean Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?dialogflow[_-]?client[_-]?email[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Dialogflow Client Email"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?deploy[_-]?user[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Deploy User Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?deploy[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Deploy Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?deploy[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Deploy Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?deploy[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Deploy Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?datadog[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Datadog API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?datadog[_-]?app[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Datadog App Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?database[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Database Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?database[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Database Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?database[_-]?name[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Database Name"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?darkpool[_-]?slack[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Darkpool Slack Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?darklaunch[_-]?dynamodb[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Darklaunch DynamoDB Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?darklaunch[_-]?dynamodb[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Darklaunch DynamoDB Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?customer[_-]?os[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Customer OS Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?customer[_-]?os[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Customer OS Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?coverity[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Coverity Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?coverity[_-]?scan[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Coverity Scan Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?contentful[_-]?personal[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Contentful Personal Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?contentful[_-]?management[_-]?api[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Contentful Management API Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?contentful[_-]?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Contentful Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?conda[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Conda Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?composer[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Composer Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cocoapods[_-]?trunk[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cocoapods Trunk Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?codecov[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Codecov Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?codeclimate[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Codeclimate Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloudinary[_-]?url[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloudinary URL"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloudinary[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloudinary Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloudinary[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloudinary Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloudflare[_-]?global[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloudflare Global API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloudflare[_-]?auth[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloudflare Auth Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloudflare[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloudflare API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloudflare[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloudflare API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloudant[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloudant Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloudant[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloudant Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloud[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloud Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloud[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloud Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cloud[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cloud Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?clojars[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Clojars Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?clojars[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Clojars Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?circleci[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "CircleCI Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?circle[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Circle Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?chrome[_-]?refresh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Chrome Refresh Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cdn[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "CDN Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cdn[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "CDN AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cassandra[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cassandra Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cassandra[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cassandra Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?cargo[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Cargo Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bugsnag[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bugsnag API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bugsnag[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bugsnag API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?browserstack[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "BrowserStack Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?branch[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Branch Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bootstrap[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bootstrap Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bitly[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bitly Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bitbucket[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bitbucket Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bitbucket[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bitbucket Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bitbucket[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bitbucket Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bitbucket[_-]?client[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bitbucket Client ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bintray[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bintray Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bintray[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bintray Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bintray[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bintray API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?b2[_-]?account[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "B2 Account ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?b2[_-]?application[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "B2 Application Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?awssecretkey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?awskey[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?awsbucket[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Bucket"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?session[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Session Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?secretsmanager[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Secrets Manager Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Secret Key Alt"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?secret[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Secret Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?s3[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS S3 Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?s3[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS S3 Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?s3[_-]?bucket[_-]?name[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS S3 Bucket Name"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?s3[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS S3 Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?iam[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS IAM Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?config[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Config Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?config[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Config Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aws[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AWS Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?auth0[_-]?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Auth0 Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?auth0[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Auth0 API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?auth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Auth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?auth[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Auth Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?auth[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Auth Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aurora[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Aurora Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aurora[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Aurora AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?artifactory[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Artifactory Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?artifactory[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Artifactory Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?artifactory[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Artifactory Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?artifactory[_-]?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Artifactory API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ansible[_-]?vault[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Ansible Vault Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?amplitude[_-]?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Amplitude API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?airbrake[_-]?project[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Airbrake Project Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aiven[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Aiven Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?adx[_-]?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "ADX Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?adx[_-]?aws[_-]?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "ADX AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?admin[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Admin Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?account[_-]?sid[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Account SID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?account[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Account Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?access[_-]?token[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Access Token Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?access[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Access Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?access[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Access Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?access[_-]?key[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Access Key Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?access[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Access Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?account[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Account Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?aes[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "AES Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?api[_-]?token[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "API Token Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?api[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "API Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?api[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "API Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?api[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "API Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?api[_-]?key[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "API Key Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?api[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "API Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?api[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "API Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?app[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "App Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?app[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "App Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?app[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "App Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?app[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "App ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?bearer[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Bearer Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?client[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Client Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?client[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Client Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?client[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Client Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?client[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Client ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?connection[_-]?string[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Connection String"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?db[_-]?connection[_-]?string[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DB Connection String"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?db[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DB Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?db[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DB Password"},
		{Pattern: regexp.MustCompile(`(?i)[\"']?encryption[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Encryption Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?github[_-]?client[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "GitHub Client ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ldap[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "LDAP Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?ldap[_-]?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "LDAP Username"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?master[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Master Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?master[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Master Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?mysql[_-]?user[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MySQL User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?oauth[_-]?token[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OAuth Token Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?oauth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "OAuth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?pass[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Pass Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?private[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Private Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?private[_-]?key[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Private Key Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?private[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Private Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?prod[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Production Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?publish[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Publish Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?refresh[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Refresh Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?key[_-]?id[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret Key ID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?session[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Session Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?session[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Session Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?signing[_-]?key[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Signing Key Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?signing[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Signing Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?slack[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Slack Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?token[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype Token Password"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?sonatype[_-]?token[_-]?user[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Sonatype Token User"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?stripe[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Stripe Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?stripe[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Stripe Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?stripe[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Stripe Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?test[_-]?access[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Test Access Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?test[_-]?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Test Secret Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?token[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Token Key"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?token[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Token Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twilio[_-]?account[_-]?sid[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twilio Account SID"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twilio[_-]?auth[_-]?token[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twilio Auth Token"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?twilio[_-]?secret[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Twilio Secret"},
	{Pattern: regexp.MustCompile(`(?i)[\"']?username[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Username"},
	
	
	
	
		{Pattern: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`), Label: "Google API Key"},
	{Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Label: "AWS Access Key ID"},
	{Pattern: regexp.MustCompile(`[A-Za-z0-9/+=]{40}`), Label: "AWS Secret Access Key"},
	{Pattern: regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`), Label: "GitHub Personal Access Token"},
	{Pattern: regexp.MustCompile(`[0-9a-f]{40}`), Label: "Generic SHA-1 Key"},
	{Pattern: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`), Label: "Google API Key"},
	
	
	
    {Pattern: regexp.MustCompile(`^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$`), Label: "Base64 Encoded String"},
    {Pattern: regexp.MustCompile(`[1-9][0-9]+-[0-9a-zA-Z]{40}`), Label: "Twitter Access Token"},
    {Pattern: regexp.MustCompile(`(^|[^@\w])@(\w{1,15})\b`), Label: "Twitter Username"},
    
    {Pattern: regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`), Label: "Facebook Access Token"},
    {Pattern: regexp.MustCompile(`[A-Za-z0-9]{125}`), Label: "Facebook OAuth 2.0 Token"},
    {Pattern: regexp.MustCompile(`[0-9a-fA-F]{7}\.[0-9a-fA-F]{32}`), Label: "Instagram OAuth 2.0 Token"},
   //{Pattern: regexp.MustCompile(`(?:@)([A-Za-z0-9_](?:(?:[A-Za-z0-9_]|(?:\.(?!\.))){0,28}(?:[A-Za-z0-9_]))?)`), Label: "Instagram Username"},
    //{Pattern: regexp.MustCompile(`(?:#)([A-Za-z0-9_](?:(?:[A-Za-z0-9_]|(?:\.(?!\.))){0,28}(?:[A-Za-z0-9_]))?)`), Label: "Instagram Hashtag"},
    {Pattern: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`), Label: "Google API Key"},
    {Pattern: regexp.MustCompile(`[0-9a-zA-Z-_]{24}`), Label: "Google OAuth 2.0 Secret Key"},
    {Pattern: regexp.MustCompile(`4/[0-9A-Za-z-_]+`), Label: "Google OAuth 2.0 Auth Code"},
    {Pattern: regexp.MustCompile(`1/[0-9A-Za-z-]{43}|1/[0-9A-Za-z-]{64}`), Label: "Google OAuth 2.0 Refresh Token"},
    {Pattern: regexp.MustCompile(`ya29\.[0-9A-Za-z-_]+`), Label: "Google OAuth 2.0 Access Token"},
    {Pattern: regexp.MustCompile(`^ghp_[a-zA-Z0-9]{36}$`), Label: "GitHub Personal Access Token (Classic)"},
    {Pattern: regexp.MustCompile(`^github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$`), Label: "GitHub Personal Access Token (Fine-Grained)"},
    {Pattern: regexp.MustCompile(`^gho_[a-zA-Z0-9]{36}$`), Label: "GitHub OAuth 2.0 Access Token"},
    {Pattern: regexp.MustCompile(`^ghu_[a-zA-Z0-9]{36}$`), Label: "GitHub User-to-Server Access Token"},
    {Pattern: regexp.MustCompile(`^ghs_[a-zA-Z0-9]{36}$`), Label: "GitHub Server-to-Server Access Token"},
    {Pattern: regexp.MustCompile(`^ghr_[a-zA-Z0-9]{36}$`), Label: "GitHub Refresh Token"},
    //{Pattern: regexp.MustCompile(`[0-9a-zA-Z_]{5,31}`), Label: "Foursquare Client Key"},
    //{Pattern: regexp.MustCompile(`R_[0-9a-f]{32}`), Label: "Foursquare Secret Key"},
    {Pattern: regexp.MustCompile(`sk_live_[0-9a-z]{32}`), Label: "Picatic API Key"},
    {Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`), Label: "Stripe Standard API Key"},
    {Pattern: regexp.MustCompile(`rk_live_[0-9a-zA-Z]{99}`), Label: "Stripe Restricted API Key"},
   
    {Pattern: regexp.MustCompile(`sq0atp-[0-9A-Za-z-_]{22}`), Label: "Square Access Token"},
    {Pattern: regexp.MustCompile(`q0csp-[0-9A-Za-z-_]{43}`), Label: "Square OAuth Secret"},
    {Pattern: regexp.MustCompile(`access_token,production$[0-9a-z]{16}[0-9a-z]{32}`), Label: "PayPal/Braintree Access Token"},
    {Pattern: regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), Label: "Amazon Marketing Services Auth Token"},
    {Pattern: regexp.MustCompile(`55[0-9a-fA-F]{32}`), Label: "Twilio Access Token"},
    {Pattern: regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), Label: "Mailgun Access Token"},
    {Pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), Label: "MailChimp Access Token"},
    {Pattern: regexp.MustCompile(`xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}`), Label: "Slack OAuth v2 Bot Access Token"},
    {Pattern: regexp.MustCompile(`xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}`), Label: "Slack OAuth v2 User Access Token"},
    {Pattern: regexp.MustCompile(`xoxe\.xoxp-1-[0-9a-zA-Z]{166}`), Label: "Slack OAuth v2 Configuration Token"},
    {Pattern: regexp.MustCompile(`xoxe-1-[0-9a-zA-Z]{147}`), Label: "Slack OAuth v2 Refresh Token"},
    {Pattern: regexp.MustCompile(`T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`), Label: "Slack Webhook"},
    {Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Label: "AWS Access ID Key"},
    {Pattern: regexp.MustCompile(`[0-9a-zA-Z/+]{40}`), Label: "AWS Secret Key"},
    {Pattern: regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), Label: "GCP OAuth 2.0 Token"},
    {Pattern: regexp.MustCompile(`[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}`), Label: "GCP API Key"},
    {Pattern: regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), Label: "Heroku API Key"},
    {Pattern: regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`), Label: "Heroku OAuth 2.0 Token"},
    {Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`), Label: "OpenAI User API Key"},
    {Pattern: regexp.MustCompile(`sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`), Label: "OpenAI User Project Key"},
    {Pattern: regexp.MustCompile(`^[A-Za-z0-9]+(-*[A-Za-z0-9]+)*$`), Label: "OpenAI Service ID"},
    {Pattern: regexp.MustCompile(`sk-[A-Za-z0-9]+(-*[A-Za-z0-9]+)*-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`), Label: "OpenAI Service Key"},
    {Pattern: regexp.MustCompile(`waka_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), Label: "WakaTime API Key"},
    {Pattern: regexp.MustCompile(`(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}`), Label: "Artifactory API Token"},
    {Pattern: regexp.MustCompile(`(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}`), Label: "Artifactory Password"},
    {Pattern: regexp.MustCompile(`basic [a-zA-Z0-9_\-\:\.=]+`), Label: "Authorization Basic"},
 
    {Pattern: regexp.MustCompile(`bearer [a-zA-Z0-9_\-\.=]+`), Label: "Authorization Bearer"},
    {Pattern: regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`), Label: "AWS Client ID"},
  
    {Pattern: regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), Label: "AWS MWS Key"},
    {Pattern: regexp.MustCompile(`(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`), Label: "AWS Secret Key"},
    {Pattern: regexp.MustCompile(`(?:[A-Z2-7]{8})*(?:[A-Z2-7]{2}={6}|[A-Z2-7]{4}={4}|[A-Z2-7]{5}={3}|[A-Z2-7]{7}=)?`), Label: "Base32 Encoded String"},
    {Pattern: regexp.MustCompile(`(eyJ|YTo|Tzo|PD[89]|aHR0cHM6L|aHR0cDo|rO0)[a-zA-Z0-9+/]+={0,2}`), Label: "Base64 Encoded String"},
    {Pattern: regexp.MustCompile(`[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+`), Label: "Basic Auth Credentials"}, // Removed lookbehind (?<=:\/\/) as Go doesn't support it
    {Pattern: regexp.MustCompile(`cloudinary:\/\/[0-9]{15}:[0-9A-Za-z]+@[a-z]+`), Label: "Cloudinary Basic Auth"},
    {Pattern: regexp.MustCompile(`(?i)(facebook|fb)(.{0,20})?['"][0-9]{13,17}`), Label: "Facebook Client ID"},
    {Pattern: regexp.MustCompile(`[fF][aA][cC][eE][bB][oO][oO][kK].*['"][0-9a-f]{32}['"]`), Label: "Facebook OAuth"},
    {Pattern: regexp.MustCompile(`(?i)(facebook|fb)(.{0,20})?['"][0-9a-f]{32}`), Label: "Facebook Secret Key"},
    {Pattern: regexp.MustCompile(`(?i)github(.{0,20})?['"][0-9a-zA-Z]{35,40}`), Label: "Github Token"},
    {Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Label: "Google API Key"},
    {Pattern: regexp.MustCompile(`(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['"]AIza[0-9a-z\-_]{35}['"]`), Label: "Google Cloud Platform API Key"},
    {Pattern: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), Label: "Google OAuth"},
    {Pattern: regexp.MustCompile(`[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`), Label: "Heroku API Key"},
    {Pattern: regexp.MustCompile(`(?i)linkedin(.{0,20})?['"][0-9a-z]{16}['"]`), Label: "LinkedIn Secret Key"},
    {Pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), Label: "Mailchimp API Key"},
    {Pattern: regexp.MustCompile(`key-[0-9a-zA-Z]{32}`), Label: "Mailgun API Key"},
    {Pattern: regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`), Label: "Slack Token"}, // Simplified optional quantifier
    {Pattern: regexp.MustCompile(`https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`), Label: "Slack Webhook"},
    {Pattern: regexp.MustCompile(`(?:r|s)k_live_[0-9a-zA-Z]{24}`), Label: "Stripe API Key"},
    {Pattern: regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`), Label: "Square Access Token"}, // Corrected 'sqOatp' to 'sq0atp'
    {Pattern: regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`), Label: "Square OAuth Secret"}, // Removed extra space
    {Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Label: "Twilio API Key"},
    {Pattern: regexp.MustCompile(`[tT][wW][iI][tT][tT][eE][rR].{0,30}['"\s][0-9a-zA-Z]{35,44}['"\s]`), Label: "Twitter OAuth"},
    {Pattern: regexp.MustCompile(`(?i)twitter(.{0,20})?['"][0-9a-z]{35,44}`), Label: "Twitter Secret Key"},
    {Pattern: regexp.MustCompile(`cloudinary://.*`), Label: "Cloudinary URL"},
    {Pattern: regexp.MustCompile(`.*firebaseio\.com`), Label: "Firebase URL"},
    {Pattern: regexp.MustCompile(`(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`), Label: "Slack Token"},
    {Pattern: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`), Label: "RSA Private Key"},
    {Pattern: regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`), Label: "SSH (DSA) Private Key"},
    {Pattern: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), Label: "SSH (EC) Private Key"},
    {Pattern: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), Label: "PGP Private Key Block"},
    {Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Label: "Amazon AWS Access Key ID"},
    {Pattern: regexp.MustCompile(`amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), Label: "Amazon MWS Auth Token"},
    {Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Label: "AWS API Key"},
    {Pattern: regexp.MustCompile(`[gG][iI][tT][hH][uU][bB].*['"][0-9a-zA-Z]{35,40}['"]`), Label: "GitHub Token"},
    {Pattern: regexp.MustCompile(`[aA][pP][iI][_]?[kK][eE][yY].*['"][0-9a-zA-Z]{32,45}['"]`), Label: "Generic API Key"},
    {Pattern: regexp.MustCompile(`[sS][eE][cC][rR][eE][tT].*['"][0-9a-zA-Z]{32,45}['"]`), Label: "Generic Secret"},
    {Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Label: "Google Cloud Platform API Key"},
    {Pattern: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), Label: "Google Cloud Platform OAuth"},
    {Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Label: "Google Drive API Key"},
    {Pattern: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), Label: "Google Drive OAuth"},
    {Pattern: regexp.MustCompile(`"type": "service_account"`), Label: "Google (GCP) Service-account"},
    {Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Label: "Google Gmail API Key"},
    {Pattern: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), Label: "Google Gmail OAuth"},
    {Pattern: regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`), Label: "Google OAuth Access Token"},
    {Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Label: "Google YouTube API Key"},
    {Pattern: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), Label: "Google YouTube OAuth"},
    {Pattern: regexp.MustCompile(`[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`), Label: "Heroku API Key"},
    {Pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), Label: "MailChimp API Key"},
    {Pattern: regexp.MustCompile(`[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s]`), Label: "Password in URL"},
    {Pattern: regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`), Label: "PayPal Braintree Access Token"},
    {Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`), Label: "Stripe API Key"},
    {Pattern: regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`), Label: "Stripe Restricted API Key"},
    {Pattern: regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`), Label: "Square Access Token"},
    {Pattern: regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`), Label: "Square OAuth Secret"},
    {Pattern: regexp.MustCompile(`[tT][wW][iI][tT][tT][eE][rR].*[1-9][0-9]+-[0-9a-zA-Z]{40}`), Label: "Twitter Access Token"},
    {Pattern: regexp.MustCompile(`[tT][wW][iI][tT][tT][eE][rR].*['"][0-9a-zA-Z]{35,44}['"]`), Label: "Twitter OAuth"},
    {Pattern: regexp.MustCompile(`(?i)aws(.{0,20})?['"][0-9a-zA-Z\/+]{40}['"]`), Label: "AWS Secret Key"},
    {Pattern: regexp.MustCompile(`[a-zA-Z0-9]+:[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]+`), Label: "Basic Auth Credentials"}, // Lookbehind (?<=:\/\/) removed
    {Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Label: "Google Youtube API Key"},
    {Pattern: regexp.MustCompile(`[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`), Label: "Google Youtube OAuth"},
    {Pattern: regexp.MustCompile(`\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b`), Label: "IPv4 Address"},
    {Pattern: regexp.MustCompile(`(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`), Label: "IPv6 Address"},
    //{Pattern: regexp.MustCompile(`(?:const|let|var)\s+(\w+?)(?=[;.=\s])`), Label: "Javascript Variable"}, // Lookahead adjusted
    //{Pattern: regexp.MustCompile(`(?i)linkedin(.{0,20})?['"][0-9a-z]{12}['"]`), Label: "LinkedIn Client ID"},
    {Pattern: regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`), Label: "Mailchimp API Key"}, // Corrected typo "Mailchamp" to "Mailchimp"
    {Pattern: regexp.MustCompile(`mailto:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+`), Label: "Mailto Email"}, // Lookbehind removed, added "mailto:"
    {Pattern: regexp.MustCompile(`[a-f0-9]{32}`), Label: "MD5 Hash"},
    {Pattern: regexp.MustCompile(`https://hooks.slack.com/services/T[a-zA-Z0-9_]{10}/B[a-zA-Z0-9_]{10}/[a-zA-Z0-9_]{24}`), Label: "Slack Webhook"},
    {Pattern: regexp.MustCompile(`(pk|sk|rk)_(test|live)_[A-Za-z0-9]+`), Label: "Stripe API Key"},
    {Pattern: regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`), Label: "Square Access Token"}, // Corrected "sqOatp" to "sq0atp"
    {Pattern: regexp.MustCompile(`(?i)twitter(.{0,20})?['"][0-9a-z]{18,25}`), Label: "Twitter Client ID"},
    {Pattern: regexp.MustCompile(`(?i)twitter(.{0,20})?['"][0-9a-z]{35,44}`), Label: "Twitter Secret Key"},
    {Pattern: regexp.MustCompile(`[sb]\.[a-zA-Z0-9]{24}`), Label: "Vault Token"},
    //{Pattern: regexp.MustCompile(`[\?&][a-zA-Z0-9_]+(?=\=)`), Label: "URL Parameter"}, // Lookbehind replaced with [\?&]
    //{Pattern: regexp.MustCompile(`https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)`), Label: "URL (With HTTP Protocol)"},
    //{Pattern: regexp.MustCompile(`[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)`), Label: "URL (Without Protocol)"},
}

var sensitivePatterns = []SecretPattern{



    // Private Keys (Highly Sensitive Cryptographic Secrets)
    {Pattern: regexp.MustCompile(`-----BEGIN PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END PRIVATE KEY-----`), Label: "Generic Private Key"},
    {Pattern: regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----[a-zA-Z0-9\\S]{100,}-----END RSA PRIVATE KEY-----`), Label: "RSA Private Key"},
    {Pattern: regexp.MustCompile(`-----BEGIN DSA PRIVATE KEY-----`), Label: "SSH (DSA) Private Key"},
    {Pattern: regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`), Label: "SSH (EC) Private Key"},
    {Pattern: regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`), Label: "PGP Private Key Block"},

    // AWS Credentials (Critical Cloud Access)
    {Pattern: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Label: "AWS Access Key ID"},
    {Pattern: regexp.MustCompile(`[A-Za-z0-9/+=]{40}`), Label: "AWS Secret Access Key"},
    {Pattern: regexp.MustCompile(`amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), Label: "Amazon MWS Auth Token"},
    {Pattern: regexp.MustCompile(`(?i)aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`), Label: "AWS Secret Key"},

    // Database and System Credentials (Direct Data Exposure)
    {Pattern: regexp.MustCompile(`(?i)[\"']?db[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DB Password"},
    {Pattern: regexp.MustCompile(`(?i)[\"']?wordpress[_-]?db[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "WordPress Database Password"},
    {Pattern: regexp.MustCompile(`(?i)[\"']?mysql[_-]?user[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "MySQL User"},
    {Pattern: regexp.MustCompile(`[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}["'\s]`), Label: "Password in URL"},
    {Pattern: regexp.MustCompile(`(?i)[\"']?db[_-]?connection[_-]?string[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "DB Connection String"},

    // Live API Keys and High-Privilege Tokens (Production Access)
    {Pattern: regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`), Label: "Stripe Live Key"},
    {Pattern: regexp.MustCompile(`sk_live_[0-9a-z]{32}`), Label: "Stripe Live Secret Key"},
    {Pattern: regexp.MustCompile(`rk_live_[0-9a-zA-Z]{24}`), Label: "Stripe Restricted Key"},
    {Pattern: regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`), Label: "GitHub Personal Access Token"},
    {Pattern: regexp.MustCompile(`^ghp_[a-zA-Z0-9]{36}$`), Label: "GitHub Personal Access Token (Classic)"},
    {Pattern: regexp.MustCompile(`^github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$`), Label: "GitHub Personal Access Token (Fine-Grained)"},
    {Pattern: regexp.MustCompile(`xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`), Label: "Slack Token"},
    {Pattern: regexp.MustCompile(`xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}`), Label: "Slack OAuth v2 Bot Access Token"},
    {Pattern: regexp.MustCompile(`xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}`), Label: "Slack OAuth v2 User Access Token"},
    {Pattern: regexp.MustCompile(`https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`), Label: "Slack Webhook"},
    {Pattern: regexp.MustCompile(`SK[0-9a-fA-F]{32}`), Label: "SendGrid API Key"},
    {Pattern: regexp.MustCompile(`AC[a-zA-Z0-9_\\-]{32}`), Label: "Twilio Account SID"},
    {Pattern: regexp.MustCompile(`AP[a-zA-Z0-9_\\-]{32}`), Label: "Twilio API Key"},
    {Pattern: regexp.MustCompile(`access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}`), Label: "Square Access Token"},
    {Pattern: regexp.MustCompile(`sq0csp-[ 0-9A-Za-z\\-_]{43}`), Label: "Square Client Secret"},
    {Pattern: regexp.MustCompile(`sqOatp-[0-9A-Za-z\\-_]{22}`), Label: "Square OAuth Token"}, // Note: Typo 'sqOatp' should be 'sq0atp'
    {Pattern: regexp.MustCompile(`[hH][eE][rR][oO][kK][uU].{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`), Label: "Heroku API Key"},

    {Pattern: regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), Label: "Google API Key"},
    
    // Google Credentials (Sensitive Cloud/Service Access)
    {Pattern: regexp.MustCompile(`ya29\\.[0-9A-Za-z\\-_]+`), Label: "Google OAuth Token"},
    {Pattern: regexp.MustCompile(`[0-9a-zA-Z-_]{24}`), Label: "Google OAuth 2.0 Secret Key"},
    {Pattern: regexp.MustCompile(`1/[0-9A-Za-z-]{43}|1/[0-9A-Za-z-]{64}`), Label: "Google OAuth 2.0 Refresh Token"},

    // Generic Sensitive Credentials (High-Risk)
    {Pattern: regexp.MustCompile(`(?i)[\"']?prod[_-]?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Production Password"},
    {Pattern: regexp.MustCompile(`(?i)[\"']?master[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Master Key"},
    {Pattern: regexp.MustCompile(`(?i)[\"']?secret[_-]?key[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Secret Key"},
    {Pattern: regexp.MustCompile(`(?i)[\"']?password[\"']?[^\\S\r\n]*[=:][^\\S\r\n]*[\"']?[\\w-]+[\"']?`), Label: "Password"},

}
//add sensitve patter is same above formet



func checkLatestVersion() string {
	url := "https://api.github.com/repos/Karthik-HR0/jadu/releases/latest"
	resp, err := http.Get(url)
	if err != nil {
		return "unknown (error checking version)"
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "unknown (error reading response)"
	}

	var release GithubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "unknown (error parsing response)"
	}

	return strings.TrimPrefix(release.TagName, "v") // Remove 'v' prefix if present
}

func req(url string) {
    if !strings.Contains(url, "http") {
        fmt.Println("\033[31m[-]\033[37m Send URLs via stdin (ex: cat js.txt | jadu). Each url must contain 'http' string.")
        os.Exit(0)
    }

    if len(*extrapattern) > 0 {
        extraPattern, err := regexp.Compile(*extrapattern)
        if err != nil {
            fmt.Printf("\033[31m[-]\033[37m Invalid regex pattern: %v\n", err)
            return
        }
        secretsPatterns = append(secretsPatterns, SecretPattern{Pattern: extraPattern, Label: "Custom Pattern"})
    }

    defer func() {
        if r := recover(); r != nil {
            return
        }
    }()

    transp := &http.Transport{
        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
    }
    httpclient := &http.Client{Transport: transp}
    req, _ := http.NewRequest("GET", url, nil)
    req.Header.Set("User-Agent", *ua)
    req.Header.Set("Cookie", *rc)

    if *detailed {
        fmt.Println("\033[33m[*]\033[37m Processing URL:", url)
    }

    r, err := httpclient.Do(req)
    if err != nil {
        fmt.Println("\033[31m[-]\033[37m Unable to make a request for", url)
        return
    }
    defer r.Body.Close()
    body, err := ioutil.ReadAll(r.Body)
    if err != nil {
        fmt.Println("\033[31m[-]\033[37m Unable to read the body of", url)
        return
    }
    strbody := string(body)

    if !*sensitive {
        for _, secretPattern := range secretsPatterns {
            matches := secretPattern.Pattern.FindAllString(strbody, -1)
            for _, secret := range matches {
                secretsMu.Lock() // Lock before accessing the map
                if secrets[secret] {
                    secretsMu.Unlock() // Unlock if skipping
                    continue
                }
                secrets[secret] = true
                secretsMu.Unlock() // Unlock after writing

                if secretPattern.Label == "Google API Key" {
                    if *detailed {
                        lines := strings.Split(strbody, "\n")
                        for i, line := range lines {
                            if strings.Contains(line, secret) {
                                fmt.Printf("\033[36m[+]\033[37m \033[33m%s\033[37m \033[35m[ %s ]\033[37m \033[32m[ %s ]\033[37m [Line: %d]\n", url, secretPattern.Label, secret, i+1)
                            }
                        }
                    } else {
                        fmt.Printf("\033[36m[+]\033[37m \033[33m%s\033[37m \033[35m[ %s ]\033[37m \033[32m[ %s ]\033[37m\n", url, secretPattern.Label, secret)
                    }
                } else {
                    if *detailed {
                        lines := strings.Split(strbody, "\n")
                        for i, line := range lines {
                            if strings.Contains(line, secret) {
                                fmt.Printf("\033[32m[+]\033[37m \033[33m%s\033[37m \033[35m[ %s ]\033[37m \033[32m[ %s ]\033[37m [Line: %d]\n", url, secretPattern.Label, secret, i+1)
                            }
                        }
                    } else {
                        fmt.Printf("\033[32m[+]\033[37m \033[33m%s\033[37m \033[35m[ %s ]\033[37m \033[32m[ %s ]\033[37m\n", url, secretPattern.Label, secret)
                    }
                }
            }
        }
    }

    for _, sensitivePattern := range sensitivePatterns {
        matches := sensitivePattern.Pattern.FindAllString(strbody, -1)
        for _, secret := range matches {
            secretsMu.Lock() // Lock before accessing the map
            if secrets[secret] {
                secretsMu.Unlock() // Unlock if skipping
                continue
            }
            secrets[secret] = true
            secretsMu.Unlock() // Unlock after writing

            if *detailed {
                lines := strings.Split(strbody, "\n")
                for i, line := range lines {
                    if strings.Contains(line, secret) {
                        fmt.Printf("\033[31m[+]\033[37m \033[33m%s\033[37m \033[35m[ %s ]\033[37m \033[31m[ %s ]\033[37m [Line: %d]\n", url, sensitivePattern.Label, secret, i+1)
                    }
                }
            } else {
                fmt.Printf("\033[31m[+]\033[37m \033[33m%s\033[37m \033[35m[ %s ]\033[37m \033[31m[ %s ]\033[37m\n", url, sensitivePattern.Label, secret)
            }
        }
    }
}

func init() {
	silent = flag.Bool("s", false, "silent")
	thread = flag.Int("t", 50, "thread number")
	ua = flag.String("ua", "Jadu", "User-Agent")
	detailed = flag.Bool("d", false, "detailed")
	rc = flag.String("c", "", "cookies")
	extrapattern = flag.String("ep", "", "extra, custom (regexp) pattern")
	sensitive = flag.Bool("sen", false, "show only sensitive API keys")
	showPatterns = flag.Bool("show-patterns", false, "display all available secret patterns and exit")
	updateCheck = flag.Bool("up", false, "check for updates")
}

func banner() {
	latestVersion := checkLatestVersion()
	versionColor := "\033[32m" // Green by default
	versionStatus := " (Latest)"
	
	if latestVersion != "unknown (error checking version)" && 
	   latestVersion != "unknown (error reading response)" && 
	   latestVersion != "unknown (error parsing response)" {
		if latestVersion > currentVersion {
			versionColor = "\033[31m" // Red for outdated
			versionStatus = " (Outdated)"
		}
	} else {
		versionColor = "\033[33m" // Yellow for unknown
		versionStatus = " (Version check failed)"
	}

	fmt.Printf(`
	
     ____.           .___     
    |    |____     __| _/_ __ 
    |    \__  \   / __ |  |  \
/\__|    |/ __ \_/ /_/ |  |  /
\________(____  /\____ |____/ 
              \/      \/      

	                           [Coded by arunthehacker]
	                            [Version %s%s%s%s]
`, versionColor, currentVersion, versionStatus, "\033[37m") // Reset color at end
}

func displayPatterns() {
	const nameWidth = 30
	const patternWidth = 103

	// Regular Secrets Table
	fmt.Println("Regular Secret Patterns:")
	fmt.Printf("╒%s╤%s╕\n", strings.Repeat("═", nameWidth), strings.Repeat("═", patternWidth))
	fmt.Printf("│ %-"+fmt.Sprint(nameWidth-1)+"s │ %-"+fmt.Sprint(patternWidth-1)+"s │\n", "Name", "Pattern")
	fmt.Printf("╞%s╪%s╡\n", strings.Repeat("═", nameWidth), strings.Repeat("═", patternWidth))

	for i, pattern := range secretsPatterns {
		name := pattern.Label
		regex := pattern.Pattern.String()
		if len(name) > nameWidth-1 {
			name = name[:nameWidth-4] + "..."
		}
		fmt.Printf("│ %-"+fmt.Sprint(nameWidth-1)+"s │ %-"+fmt.Sprint(patternWidth-1)+"s │\n", name, regex)
		if i < len(secretsPatterns)-1 {
			fmt.Printf("├%s┼%s┤\n", strings.Repeat("─", nameWidth), strings.Repeat("─", patternWidth))
		}
	}
	fmt.Printf("╘%s╧%s╛\n", strings.Repeat("═", nameWidth), strings.Repeat("═", patternWidth))

	// Spacing between tables
	fmt.Println("\n")

	// Sensitive Patterns Table
	fmt.Println("Sensitive Secret Patterns:")
	fmt.Printf("╒%s╤%s╕\n", strings.Repeat("═", nameWidth), strings.Repeat("═", patternWidth))
	fmt.Printf("│ %-"+fmt.Sprint(nameWidth-1)+"s │ %-"+fmt.Sprint(patternWidth-1)+"s │\n", "Name", "Pattern")
	fmt.Printf("╞%s╪%s╡\n", strings.Repeat("═", nameWidth), strings.Repeat("═", patternWidth))

	for i, pattern := range sensitivePatterns {
		name := pattern.Label
		regex := pattern.Pattern.String()
		if len(name) > nameWidth-1 {
			name = name[:nameWidth-4] + "..."
		}
		fmt.Printf("│ %-"+fmt.Sprint(nameWidth-1)+"s │ %-"+fmt.Sprint(patternWidth-1)+"s │\n", name, regex)
		if i < len(sensitivePatterns)-1 {
			fmt.Printf("├%s┼%s┤\n", strings.Repeat("─", nameWidth), strings.Repeat("─", patternWidth))
		}
	}
	fmt.Printf("╘%s╧%s╛\n", strings.Repeat("═", nameWidth), strings.Repeat("═", patternWidth))
}

func main() {
	stdin := bufio.NewScanner(os.Stdin)
	urls := make(chan string)
	var wg sync.WaitGroup
	flag.Parse()

	if *updateCheck {
		latest := checkLatestVersion()
		if latest == currentVersion {
			fmt.Printf("\033[32m[+] Version %s is the latest version\033[37m\n", currentVersion)
		} else if strings.HasPrefix(latest, "unknown") {
			fmt.Printf("\033[33m[-] Could not check version: %s\033[37m\n", latest)
		} else {
			fmt.Printf("\033[31m[-] Version %s is outdated. Latest version is %s\033[37m\n", currentVersion, latest)
		}
		return
	}

	if *showPatterns {
		displayPatterns()
		return
	}

	if !*silent {
		banner()
	}
	for i := 0; i < *thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range urls {
				req(url)
			}
		}()
	}
	for stdin.Scan() {
		urls <- stdin.Text()
	}
	close(urls)
	wg.Wait()
}
