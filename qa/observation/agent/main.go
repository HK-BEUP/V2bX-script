// The renewal agent never executes V2bX, changes proxy config, or enforces bans.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

const directory = "/etc/beup-observe"
const maxBytes = 8 * 1024 * 1024

var rejected = errors.New("observation delivery unavailable; proxy unchanged")
var nodePattern = regexp.MustCompile("^[a-zA-Z0-9_-]{1,64}$")
var hex64 = regexp.MustCompile("^[a-f0-9]{64}$")
var hex16 = regexp.MustCompile("^[a-f0-9]{16}$")
var hex32 = regexp.MustCompile("^[a-f0-9]{32}$")

type Ticket struct {
	Node            string `json:"node"`
	Code            string `json:"code"`
	ExpiresAt       int64  `json:"expires_at"`
	PublicKey       string `json:"public_key"`
	Endpoint        string `json:"endpoint"`
	APIHost         string `json:"api_host"`
	NodeIDs         []int  `json:"node_ids"`
	ObservationOnly bool   `json:"observation_only"`
}
type ClientState struct {
	Node        string `json:"node"`
	DeviceKey   string `json:"device_key"`
	PublicKey   string `json:"public_key"`
	Endpoint    string `json:"endpoint"`
	APIHost     string `json:"api_host"`
	NodeIDs     []int  `json:"node_ids"`
	Sequence    int64  `json:"sequence"`
	IssuedAt    int64  `json:"issued_at"`
	ExpiresAt   int64  `json:"expires_at"`
	Fingerprint string `json:"fingerprint"`
}
type Envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type Claims struct {
	Version          int                       `json:"version"`
	Node             string                    `json:"node"`
	Sequence         int64                     `json:"sequence"`
	IssuedAt         int64                     `json:"issued_at"`
	ExpiresAt        int64                     `json:"expires_at"`
	IdentityRevision string                    `json:"identity_revision"`
	Endpoint         string                    `json:"endpoint"`
	KeyID            string                    `json:"key_id"`
	ObservationKey   string                    `json:"observation_key"`
	Bindings         map[string]map[int]string `json:"bindings"`
}
type Reply struct {
	Data struct {
		Envelope        Envelope `json:"envelope"`
		RenewAfter      int      `json:"renew_after_seconds"`
		ObservationOnly bool     `json:"observation_only"`
	} `json:"data"`
}

func strict(b []byte, v any) error {
	if len(b) > maxBytes {
		return rejected
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return rejected
	}
	return nil
}
func safeURL(raw, path string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && (path == "" || u.EscapedPath() == path)
}
func valid(s ClientState) bool {
	if !nodePattern.MatchString(s.Node) || !hex64.MatchString(s.DeviceKey) || !hex64.MatchString(s.PublicKey) || !safeURL(s.Endpoint, "/api/v1/attack-guard/observation") || !safeURL(s.APIHost, "") || len(s.NodeIDs) == 0 || len(s.NodeIDs) > 100 {
		return false
	}
	ids := map[int]bool{}
	for _, id := range s.NodeIDs {
		if id <= 0 || ids[id] {
			return false
		}
		ids[id] = true
	}
	return true
}
func privateDir(dir string) error {
	real, e := filepath.EvalSymlinks(dir)
	if e != nil || real != dir {
		return rejected
	}
	st, e := os.Lstat(dir)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return rejected
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != os.Geteuid() {
		return rejected
	}
	return nil
}
func readPrivate(path string) ([]byte, error) {
	if privateDir(filepath.Dir(path)) != nil {
		return nil, rejected
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || st.Size() > maxBytes {
		return nil, rejected
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || int(sys.Uid) != os.Geteuid() {
		return nil, rejected
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, rejected
	}
	defer f.Close()
	opened, e := f.Stat()
	if e != nil || !os.SameFile(st, opened) {
		return nil, rejected
	}
	b, e := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if e != nil || len(b) > maxBytes {
		return nil, rejected
	}
	return b, nil
}
func writePrivate(path string, v any) error {
	if privateDir(filepath.Dir(path)) != nil {
		return rejected
	}
	if _, e := os.Lstat(path); e == nil {
		if _, e = readPrivate(path); e != nil {
			return rejected
		}
	} else if !os.IsNotExist(e) {
		return rejected
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > maxBytes {
		return rejected
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".stage-")
	if e != nil {
		return rejected
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if e = f.Chmod(0600); e != nil {
		return rejected
	}
	if _, e = f.Write(b); e != nil {
		return rejected
	}
	if f.Sync() != nil || f.Close() != nil {
		return rejected
	}
	if os.Rename(name, path) != nil {
		return rejected
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return rejected
	}
	defer d.Close()
	return d.Sync()
}
func locked(dir string, fn func() error) error {
	if privateDir(dir) != nil {
		return rejected
	}
	path := filepath.Join(dir, "agent.lock")
	fd, e := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return rejected
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 || int(st.Sys().(*syscall.Stat_t).Uid) != os.Geteuid() {
		return rejected
	}
	if syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return rejected
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	return fn()
}
func deliveryClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, MaxIdleConns: 1}}
}
func exchange(client *http.Client, s ClientState, action, credential string) (Reply, error) {
	var result Reply
	if !valid(s) || (action != "enroll" && action != "renew") || !hex64.MatchString(credential) {
		return result, rejected
	}
	u, _ := url.Parse(s.Endpoint)
	u.Path = "/api/v1/attack-guard/delivery/" + action
	u.RawPath = ""
	data := map[string]string{"node": s.Node}
	if action == "enroll" {
		data["device_key"] = s.DeviceKey
	}
	b, _ := json.Marshal(data)
	req, e := http.NewRequest("POST", u.String(), bytes.NewReader(b))
	if e != nil {
		return result, rejected
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("Content-Type", "application/json")
	r, e := client.Do(req)
	if e != nil {
		return result, rejected
	}
	defer r.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if e != nil || r.StatusCode != 200 || strict(raw, &result) != nil || !result.Data.ObservationOnly || result.Data.RenewAfter != 120 {
		return result, rejected
	}
	return result, nil
}
func verify(s ClientState, env Envelope, now int64) (Claims, string, error) {
	var c Claims
	key, e := hex.DecodeString(s.PublicKey)
	if e != nil || len(key) != ed25519.PublicKeySize {
		return c, "", rejected
	}
	sig, e := hex.DecodeString(env.Signature)
	if e != nil {
		return c, "", rejected
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if e != nil || len(raw) > maxBytes || !ed25519.Verify(key, append([]byte("BEUP-OBSERVATION-REGISTRY-V1\n"), raw...), sig) || strict(raw, &c) != nil {
		return c, "", rejected
	}
	if c.Version != 1 || c.Node != s.Node || c.Endpoint != s.Endpoint || c.Sequence < 1 || c.Sequence < s.Sequence || c.IssuedAt > now+30 || c.ExpiresAt <= now || c.ExpiresAt-c.IssuedAt > 900 || c.ExpiresAt <= c.IssuedAt || c.IssuedAt < s.IssuedAt || c.ExpiresAt < s.ExpiresAt || !hex64.MatchString(c.ObservationKey) || !hex16.MatchString(c.KeyID) || !nodePattern.MatchString(c.IdentityRevision) {
		return c, "", rejected
	}
	if len(c.Bindings) != len(s.NodeIDs) {
		return c, "", rejected
	}
	count := 0
	subjects := map[string]int{}
	for _, id := range s.NodeIDs {
		users, ok := c.Bindings["["+s.APIHost+"]-vless:"+strconv.Itoa(id)]
		if !ok || users == nil {
			return c, "", rejected
		}
		for uid, subject := range users {
			count++
			if count > 50000 || uid < 1 || !hex32.MatchString(subject) {
				return c, "", rejected
			}
			if old, ok := subjects[subject]; ok && old != uid {
				return c, "", rejected
			}
			subjects[subject] = uid
		}
	}
	stable := c
	stable.IssuedAt = 0
	stable.ExpiresAt = 0
	b, _ := json.Marshal(stable)
	sum := sha256.Sum256(b)
	fingerprint := hex.EncodeToString(sum[:])
	if c.Sequence == s.Sequence && s.Fingerprint != "" && s.Fingerprint != fingerprint {
		return c, "", rejected
	}
	return c, fingerprint, nil
}
func accept(dir string, s ClientState, env Envelope, now int64) error {
	c, fp, e := verify(s, env, now)
	if e != nil {
		return e
	}
	s.Sequence = c.Sequence
	s.IssuedAt = c.IssuedAt
	s.ExpiresAt = c.ExpiresAt
	s.Fingerprint = fp
	// Persist the high-water mark before delivery. A crash fails observation closed;
	// the next timer run repairs the files. V2bX forwarding is never controlled here.
	if writePrivate(filepath.Join(dir, "client.json"), s) != nil {
		return rejected
	}
	bootstrap := map[string]any{"enabled": true, "mode": "observe", "node": s.Node, "endpoint": s.Endpoint,
		"registration": map[string]any{"path": filepath.Join(dir, "lease.json"), "public_key": s.PublicKey, "minimum_sequence": s.Sequence}}
	if writePrivate(filepath.Join(dir, "settings.json"), bootstrap) != nil {
		return rejected
	}
	return writePrivate(filepath.Join(dir, "lease.json"), env)
}
func loadClient(dir string) (ClientState, error) {
	var s ClientState
	b, e := readPrivate(filepath.Join(dir, "client.json"))
	if e != nil || strict(b, &s) != nil || !valid(s) {
		return s, rejected
	}
	return s, nil
}
func join(dir string, t Ticket, client *http.Client, now int64) error {
	if !t.ObservationOnly || t.ExpiresAt <= now || t.ExpiresAt > now+600 || !hex64.MatchString(t.Code) {
		return rejected
	}
	s := ClientState{Node: t.Node, Endpoint: t.Endpoint, PublicKey: t.PublicKey, APIHost: t.APIHost, NodeIDs: t.NodeIDs}
	key := make([]byte, 32)
	if _, e := rand.Read(key); e != nil {
		return rejected
	}
	s.DeviceKey = hex.EncodeToString(key)
	if !valid(s) {
		return rejected
	}
	return locked(dir, func() error {
		if _, e := os.Lstat(filepath.Join(dir, "client.json")); e == nil {
			old, e := loadClient(dir)
			if e != nil {
				return e
			}
			a := s
			a.DeviceKey = old.DeviceKey
			a.Sequence = old.Sequence
			a.IssuedAt = old.IssuedAt
			a.ExpiresAt = old.ExpiresAt
			a.Fingerprint = old.Fingerprint
			b1, _ := json.Marshal(a)
			b2, _ := json.Marshal(old)
			if !bytes.Equal(b1, b2) {
				return rejected
			}
			s = old
		} else if !os.IsNotExist(e) {
			return rejected
		}
		if writePrivate(filepath.Join(dir, "client.json"), s) != nil {
			return rejected
		}
		result, e := exchange(client, s, "enroll", t.Code)
		if e != nil {
			return e
		}
		return accept(dir, s, result.Data.Envelope, now)
	})
}
func renew(dir string, client *http.Client, now int64) error {
	return locked(dir, func() error {
		s, e := loadClient(dir)
		if e != nil {
			return e
		}
		r, e := exchange(client, s, "renew", s.DeviceKey)
		if e != nil {
			return e
		}
		return accept(dir, s, r.Data.Envelope, now)
	})
}
func check(dir string, now int64) error {
	s, e := loadClient(dir)
	if e != nil {
		return e
	}
	b, e := readPrivate(filepath.Join(dir, "lease.json"))
	if e != nil {
		return e
	}
	var env Envelope
	if strict(b, &env) != nil {
		return rejected
	}
	_, _, e = verify(s, env, now)
	return e
}
func main() {
	if len(os.Args) != 2 || os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "root required; use enroll, renew or check")
		os.Exit(2)
	}
	client := deliveryClient()
	defer client.CloseIdleConnections()
	now := time.Now().Unix()
	var e error
	switch os.Args[1] {
	case "enroll":
		var t Ticket
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 16385))
		if err != nil || len(b) > 16384 || strict(b, &t) != nil {
			e = rejected
			break
		}
		e = join(directory, t, client, now)
	case "renew":
		e = renew(directory, client, now)
	case "check":
		e = check(directory, now)
	default:
		e = rejected
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "observation delivery unavailable; proxy unchanged")
		os.Exit(1)
	}
	fmt.Println("{\"ok\":true,\"observation_only\":true}")
}
