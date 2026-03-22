// main.go
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

//////////////////////////////
// config
//////////////////////////////

type Config struct {
	SNIProxy struct {
		Port int `yaml:"port"`
	} `yaml:"sni_proxy"`

	Upstream struct {
		Proxy              string `yaml:"proxy"`
		InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
		Auth               struct {
			Mode     string `yaml:"mode"`
			Username string `yaml:"username"`
			Password string `yaml:"password"`
			Domain   string `yaml:"domain"`
		} `yaml:"auth"`
	} `yaml:"upstream"`

	Hosts       map[string]string `yaml:"hosts"`
	HostMapping []Mapping         `yaml:"host_mapping"`
}

type Mapping struct {
	SNI     string   `yaml:"sni"`
	Port    int      `yaml:"port"`
	Pattern []string `yaml:"pattern"`
}

//////////////////////////////
// logger
//////////////////////////////

func logConn(s string)  { log.Println("[#]", s) }
func logInfo(s string)  { log.Println("[.]", s) }
func logMatch(s string) { log.Println("[?]", s) }
func logErr(s string)   { log.Println("[!]", s) }
func logFatal(s string) { log.Fatalln("!!!", s) }

//////////////////////////////
// global
//////////////////////////////

var cfg Config
var caCert *x509.Certificate
var caKey *rsa.PrivateKey

var certCache = struct {
	sync.Mutex
	m map[string]*tls.Certificate
}{m: map[string]*tls.Certificate{}}

//////////////////////////////
// main
//////////////////////////////

func main() {

	if len(os.Args) < 2 {
		fmt.Println("usage: sni-proxy config.yml")
		return
	}

	loadConfig(os.Args[1])
	initCA()

	addr := fmt.Sprintf(":%d", cfg.SNIProxy.Port)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logFatal(err.Error())
	}

	logInfo("listening " + addr)

	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(c)
	}
}

//////////////////////////////
// config
//////////////////////////////

func loadConfig(p string) {
	b, err := os.ReadFile(p)
	if err != nil {
		logFatal(err.Error())
	}
	err = yaml.Unmarshal(b, &cfg)
	if err != nil {
		logFatal(err.Error())
	}
}

//////////////////////////////
// connection
//////////////////////////////

func handleConn(c net.Conn) {
	defer c.Close()

	br := bufio.NewReader(c)

	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		handleHTTPS(c, req)
	} else {
		handleHTTP(c, req)
	}
}

//////////////////////////////
// match
//////////////////////////////

func matchHost(host string) *Mapping {
	host = strings.Split(host, ":")[0]

	for _, m := range cfg.HostMapping {
		for _, p := range m.Pattern {
			if wildcardMatch(p, host) {
				logMatch(host + " -> " + m.SNI)
				return &m
			}
		}
	}
	return nil
}

func wildcardMatch(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return strings.EqualFold(pattern, host)
}

//////////////////////////////
// HTTP
//////////////////////////////

func handleHTTP(client net.Conn, req *http.Request) {

	m := matchHost(req.Host)
	if m == nil {
		logErr("no mapping: " + req.Host)
		return
	}

	up, err := dialUpstream(m)
	if err != nil {
		logErr(err.Error())
		return
	}

	req.Write(up)
	io.Copy(client, up)
}

//////////////////////////////
// HTTPS MITM
//////////////////////////////

func handleHTTPS(client net.Conn, req *http.Request) {

	host := req.Host
	logConn("CONNECT " + host)

	m := matchHost(host)
	if m == nil {
		logErr("no mapping")
		return
	}

	io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n")

	cert := getCert(host)

	tlsClient := tls.Server(client, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})

	err := tlsClient.Handshake()
	if err != nil {
		logErr(err.Error())
		return
	}

	br := bufio.NewReader(tlsClient)
	r, err := http.ReadRequest(br)
	if err != nil {
		return
	}

	up, err := dialUpstream(m)
	if err != nil {
		return
	}

	r.Write(up)
	io.Copy(tlsClient, up)
}

//////////////////////////////
// upstream
//////////////////////////////

func dialUpstream(m *Mapping) (net.Conn, error) {

	port := m.Port
	if port == 0 {
		port = 443
	}

	addr := fmt.Sprintf("%s:%d", m.SNI, port)

	raw, err := dialViaProxy(addr)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(raw, &tls.Config{
		ServerName:         m.SNI,
		InsecureSkipVerify: cfg.Upstream.InsecureSkipVerify,
		NextProtos:         []string{"http/1.1"},
	})

	return tlsConn, tlsConn.Handshake()
}

//////////////////////////////
// proxy connect
//////////////////////////////

func dialViaProxy(target string) (net.Conn, error) {

	if cfg.Upstream.Proxy == "" {
		return net.Dial("tcp", target)
	}

	u, _ := url.Parse(cfg.Upstream.Proxy)

	conn, err := net.Dial("tcp", u.Host)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer

	fmt.Fprintf(&buf, "CONNECT %s HTTP/1.1\r\n", target)
	fmt.Fprintf(&buf, "Host: %s\r\n", target)

	auth := buildAuth()
	if auth != "" {
		fmt.Fprintf(&buf, "Proxy-Authorization: %s\r\n", auth)
	}

	buf.WriteString("\r\n")

	conn.Write(buf.Bytes())

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("proxy connect fail %s", resp.Status)
	}

	return conn, nil
}

//////////////////////////////
// auth
//////////////////////////////

func buildAuth() string {

	mode := strings.ToLower(cfg.Upstream.Auth.Mode)

	switch mode {
	case "basic":
		return basicAuth(
			cfg.Upstream.Auth.Username,
			cfg.Upstream.Auth.Password,
		)
	}

	return ""
}

func basicAuth(u, p string) string {
	token := base64.StdEncoding.EncodeToString([]byte(u + ":" + p))
	return "Basic " + token
}

//////////////////////////////
// CA
//////////////////////////////

func initCA() {

	var err error

	caKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		logFatal(err.Error())
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "SNI Proxy CA",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),

		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)

	caCert, _ = x509.ParseCertificate(der)

	f, _ := os.Create("ca.crt")
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.Close()

	logInfo("ca.crt generated")
}

//////////////////////////////
// cert cache
//////////////////////////////

func getCert(host string) *tls.Certificate {

	certCache.Lock()
	defer certCache.Unlock()

	if c, ok := certCache.m[host]; ok {
		return c
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:  []string{host},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage: x509.KeyUsageDigitalSignature,
	}

	der, _ := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)

	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}

	certCache.m[host] = cert

	return cert
}
