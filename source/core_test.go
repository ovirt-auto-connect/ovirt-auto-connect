package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func testCA(srv *httptest.Server) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
}

func TestConnectionFileRoundTrip(t *testing.T) {
	started := false
	oauthCalls := 0
	apiCalls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			oauthCalls++
			if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" || r.Header.Get("Accept") != "application/json" {
				t.Errorf("incorrect SSO headers or method")
			}
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.PostForm.Get("grant_type") != "password" || r.PostForm.Get("scope") != "ovirt-app-api" || r.PostForm.Get("username") != "testuser@internal" || r.PostForm.Get("password") != "topsecret" {
				t.Errorf("incorrect SSO request parameters")
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"secret-token","token_type":"bearer"}`)
			return
		}
		apiCalls++
		if r.Header.Get("Authorization") != "Bearer secret-token" || r.Header.Get("Version") != "4" {
			t.Errorf("incorrect API authorization/version: %q %q", r.Header.Get("Authorization"), r.Header.Get("Version"))
			w.WriteHeader(401)
			return
		}
		if _, _, ok := r.BasicAuth(); ok {
			t.Error("API Basic authentication must not be used")
		}
		w.Header().Set("Content-Type", "application/xml")
		switch r.URL.Path {
		case "/ovirt-engine/api/vms":
			if r.URL.Query().Get("search") != "name=my vm" {
				t.Errorf("bad search: %q", r.URL.RawQuery)
			}
			fmt.Fprint(w, `<vms><vm id="111"><name>different vm</name><status>up</status></vm><vm id="222"><name>my vm</name><status>down</status></vm></vms>`)
		case "/ovirt-engine/api/vms/222/start":
			if r.Method != http.MethodPost {
				t.Error("expected POST")
			}
			started = true
			fmt.Fprint(w, `<action/>`)
		case "/ovirt-engine/api/vms/222":
			if !started {
				t.Error("VM not started")
			}
			fmt.Fprint(w, `<vm id="222"><name>my vm</name><status>up</status></vm>`)
		case "/ovirt-engine/api/vms/222/graphicsconsoles":
			fmt.Fprint(w, `<graphics_consoles><graphics_console id="1"><protocol>vnc</protocol></graphics_console><graphics_console id="2"><protocol>spice</protocol></graphics_console></graphics_consoles>`)
		case "/ovirt-engine/api/vms/222/graphicsconsoles/2/remoteviewerconnectionfile":
			if r.Method != http.MethodPost {
				t.Error("expected POST")
			}
			fmt.Fprint(w, `<action><remote_viewer_connection_file>[virt-viewer]
type=spice
host=192.168.1.20
password=token</remote_viewer_connection_file></action>`)
		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "testuser", "topsecret", "internal", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	file, err := client.getConnectionFile(context.Background(), "my vm", time.Second, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if !started || !strings.Contains(file, "password=token") {
		t.Fatalf("incorrect connection file or start")
	}
	if oauthCalls != 1 || apiCalls != 5 {
		t.Fatalf("unexpected call counts: SSO %d API %d", oauthCalls, apiCalls)
	}
}

func TestExpiredTokenRefresh(t *testing.T) {
	tokenNumber, apiCalls := 0, 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			tokenNumber++
			fmt.Fprintf(w, `{"access_token":"token-%d"}`, tokenNumber)
			return
		}
		apiCalls++
		if r.Header.Get("Authorization") == "Bearer token-1" {
			w.WriteHeader(401)
			return
		}
		if r.Header.Get("Authorization") != "Bearer token-2" {
			t.Error("token not renewed")
		}
		fmt.Fprint(w, `<vms/>`)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "a@internal", "pass", "internal", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	if client.username != "a@internal" {
		t.Errorf("duplicate profile in login: %q", client.username)
	}
	var list vmList
	if err := client.request(context.Background(), http.MethodGet, "/vms", nil, "", &list); err != nil {
		t.Fatal(err)
	}
	if tokenNumber != 2 || apiCalls != 2 {
		t.Errorf("expected exactly one retry: tokens=%d requests=%d", tokenNumber, apiCalls)
	}
}

func TestInvalidSSOCredentials(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ovirt-engine/sso/oauth/token" {
			t.Error("should not call API without SSO token")
		}
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"invalid_grant", "password":"pass-private"}`)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "a", "pass-private", "internal", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	err = client.request(context.Background(), http.MethodGet, "/vms", nil, "", &vmList{})
	if err == nil || !strings.Contains(err.Error(), "SSO") || strings.Contains(err.Error(), "pass-private") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRedirectSSOIsNotFollowed(t *testing.T) {
	hits := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Location", "https://elsewhere.example/oauth")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "a", "pass-private", "internal", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	err = client.request(context.Background(), http.MethodGet, "/vms", nil, "", &vmList{})
	if err == nil || !strings.Contains(err.Error(), "307") || hits != 1 {
		t.Errorf("redirect security check failed: %v, hits=%d", err, hits)
	}
}

func TestInvalidCertificateAndURL(t *testing.T) {
	if _, err := newClient("http://example.com", "a", "b", "internal", []byte("invalid")); err == nil {
		t.Fatal("HTTP URL accepted")
	}
	if _, err := newClient("https://example.com", "a", "b", "internal", []byte("invalid")); err == nil {
		t.Fatal("invalid CA accepted")
	}
}

func TestNoMatchingVM(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			fmt.Fprint(w, `{"access_token":"token"}`)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<vms><vm id="1"><name>my-vm-2</name><status>up</status></vm></vms>`)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "a", "b", "internal", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	_, err = client.getConnectionFile(context.Background(), "my-vm", time.Second, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "не найдена") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSSOBadRequestDescribesReasonWithoutExposingCredentials(t *testing.T) {
	secret := "a&b+my pass"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ovirt-engine/sso/oauth/token" {
			t.Errorf("API request must not happen before authentication")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if got := r.PostForm.Get("password"); got != secret {
			t.Fatalf("password encoding changed: %q", got)
		}
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, `{"error":"invalid_grant","error_description":"Cannot authenticate user: %s (and %s)"}`, secret, url.QueryEscape(secret))
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "dev", secret, "eltex", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	var list vmList
	err = client.request(context.Background(), http.MethodGet, "/vms", nil, "", &list)
	if err == nil || !strings.Contains(err.Error(), "HTTP 400: invalid_grant") || !strings.Contains(err.Error(), "Cannot authenticate") {
		t.Fatalf("SSO response reason missing: %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), url.QueryEscape(secret)) {
		t.Fatalf("secret exposed by SSO error: %v", err)
	}
}

func TestSSOBadRequestHTMLDoesNotLeakRawBody(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<html>hidden-origin-details</html>`)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "dev", "pass", "internal", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	err = client.request(context.Background(), http.MethodGet, "/vms", nil, "", &vmList{})
	if err == nil || !strings.Contains(err.Error(), "HTML") || strings.Contains(err.Error(), "hidden-origin-details") {
		t.Fatalf("SSO non-OAuth error: %v", err)
	}
}

func TestMakeOVirtLoginWithLDAPUPN(t *testing.T) {
	cases := []struct{ user, profile, want string }{
		{"alice", "internal", "alice@internal"},
		{"alice@internal", "internal", "alice@internal"},
		{"alice@corp.example", "LDAP", "alice@corp.example@LDAP"},
		{"alice@corp.example@LDAP", "LDAP", "alice@corp.example@LDAP"},
		{"ALICE@INTERNAL", "internal", "ALICE@INTERNAL"},
	}
	for _, c := range cases {
		if got := makeOVirtLogin(c.user, c.profile); got != c.want {
			t.Errorf("user=%q, profile=%q: got %q, want %q", c.user, c.profile, got, c.want)
		}
	}
}

func TestFindVMCaseInsensitive(t *testing.T) {
	searched := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			fmt.Fprint(w, `{"access_token":"token"}`)
			return
		}
		if r.URL.Path != "/ovirt-engine/api/vms" {
			t.Errorf("unexpected path %s", r.URL.Path)
			return
		}
		searched++
		if r.URL.Query().Get("search") != "name=Linux" {
			t.Errorf("incorrect search %s", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<vms><vm id="1"><name>linux</name><status>up</status></vm></vms>`)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "user", "secret", "eltex", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	selected, err := client.findVM(context.Background(), "Linux")
	if err != nil || selected.Name != "linux" || selected.ID != "1" || searched != 1 {
		t.Fatalf("case-insensitive match failed: %+v, %v, %d", selected, err, searched)
	}
}

func TestFindVMReturnsAvailableAlternatives(t *testing.T) {
	searched, listed := 0, 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			fmt.Fprint(w, `{"access_token":"token"}`)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Has("search") {
			searched++
			fmt.Fprint(w, `<vms/>`)
			return
		}
		listed++
		fmt.Fprint(w, `<vms><vm id="1"><name>Linux-ESR</name><status>up</status></vm><vm id="2"><name>Linux-test</name><status>down</status></vm></vms>`)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "user", "secret", "eltex", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	_, err = client.findVM(context.Background(), "Linux")
	var notFound *vmNotFoundError
	if !errors.As(err, &notFound) || len(notFound.Available) != 2 || searched != 1 || listed != 1 {
		t.Fatalf("missing alternatives: %#v, %v, %d, %d", notFound, err, searched, listed)
	}
}

func TestFindVMFallbackToFullList(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			fmt.Fprint(w, `{"access_token":"token"}`)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		if r.URL.Query().Has("search") {
			fmt.Fprint(w, `<vms/>`)
		} else {
			fmt.Fprint(w, `<vms><vm id="7"><name>Linux</name><status>down</status></vm></vms>`)
		}
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "user", "secret", "eltex", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	selected, err := client.findVM(context.Background(), "Linux")
	if err != nil || selected.ID != "7" {
		t.Fatalf("fallback failed: %+v, %v", selected, err)
	}
}

func TestEmptyVMSelectsFirstFromServerWithoutSorting(t *testing.T) {
	searches, lists := 0, 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			fmt.Fprint(w, `{"access_token":"token"}`)
			return
		}
		if r.URL.Path != "/ovirt-engine/api/vms" {
			t.Errorf("unexpected path %s", r.URL.Path)
			return
		}
		if r.URL.Query().Has("search") {
			searches++
		} else {
			lists++
		}
		w.Header().Set("Content-Type", "application/xml")
		fmt.Fprint(w, `<vms><vm id="z"><name>Zebra</name><status>up</status></vm><vm id="a"><name>Alpha</name><status>up</status></vm></vms>`)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "testuser", "testpass", "internal", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	selected, err := client.resolveVM(context.Background(), "")
	if err != nil || selected.ID != "z" || selected.Name != "Zebra" {
		t.Fatalf("expected first returned VM, got %#v, %v", selected, err)
	}
	if lists != 1 || searches != 0 {
		t.Fatalf("expected unfiltered list only, got lists %d searches %d", lists, searches)
	}
}

func TestSpecifiedVMUsesSearch(t *testing.T) {
	searched := false
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			fmt.Fprint(w, `{"access_token":"token"}`)
			return
		}
		if r.URL.Query().Get("search") != "name=Alpha" {
			t.Errorf("expected name search, got %s", r.URL.RawQuery)
		}
		searched = true
		fmt.Fprint(w, `<vms><vm id="a"><name>Alpha</name><status>up</status></vm></vms>`)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "u", "p", "internal", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	selected, err := client.resolveVM(context.Background(), "Alpha")
	if err != nil || selected.ID != "a" || !searched {
		t.Fatalf("expected filtered VM, got %#v, %v, searched=%t", selected, err, searched)
	}
}

func TestEmptyVMListReturnsError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ovirt-engine/sso/oauth/token" {
			fmt.Fprint(w, `{"access_token":"token"}`)
			return
		}
		fmt.Fprint(w, `<vms/>`)
	}))
	defer srv.Close()
	client, err := newClient(srv.URL+"/ovirt-engine/api", "u", "p", "internal", testCA(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	_, err = client.resolveVM(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "ни одной") {
		t.Fatalf("expected empty list error, got %v", err)
	}
}
