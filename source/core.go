package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultAPIURL = "https://ovirt.eltex.loc/ovirt-engine/api"

type vmList struct {
	Items []vm `xml:"vm"`
}
type vm struct {
	ID     string `xml:"id,attr"`
	Name   string `xml:"name"`
	Status string `xml:"status"`
}

type vmNotFoundError struct {
	Name      string
	Available []vm
}

func (e *vmNotFoundError) Error() string {
	if len(e.Available) == 0 {
		return fmt.Sprintf("ВМ %q не найдена. Сервер не возвращает ни одной доступной ВМ для этой учётной записи. Проверьте права пользователя.", e.Name)
	}
	return fmt.Sprintf("ВМ %q не найдена. Доступны другие виртуальные машины.", e.Name)
}

func (o *ovirtClient) listVMs(ctx context.Context) ([]vm, error) {
	var list vmList
	if err := o.request(ctx, http.MethodGet, "/vms", url.Values{"max": {"1000"}}, "", &list); err != nil {
		return nil, err
	}
	return list.Items, nil
}

func matchVM(items []vm, name string) (vm, bool, error) {
	exact := make([]vm, 0, 1)
	folded := make([]vm, 0, 1)
	for _, item := range items {
		if item.Name == name {
			exact = append(exact, item)
		} else if strings.EqualFold(item.Name, name) {
			folded = append(folded, item)
		}
	}
	matches := exact
	if len(matches) == 0 {
		matches = folded
	}
	if len(matches) > 1 {
		return vm{}, false, fmt.Errorf("найдено несколько ВМ с именем %q. Уточните имя или обратитесь к администратору", name)
	}
	if len(matches) == 1 {
		return matches[0], true, nil
	}
	return vm{}, false, nil
}

// resolveVM mirrors the original script: use the explicitly configured name,
// otherwise use the first VM in the order returned by oVirt (not alphabetically).
func (o *ovirtClient) resolveVM(ctx context.Context, name string) (vm, error) {
	if name = strings.TrimSpace(name); name != "" {
		return o.findVM(ctx, name)
	}
	vms, err := o.listVMs(ctx)
	if err != nil {
		return vm{}, err
	}
	if len(vms) == 0 {
		return vm{}, errors.New("oVirt не вернул ни одной доступной виртуальной машины")
	}
	return vms[0], nil
}

func (o *ovirtClient) findVM(ctx context.Context, name string) (vm, error) {
	var filtered vmList
	if err := o.request(ctx, http.MethodGet, "/vms", url.Values{"search": {"name=" + name}, "max": {"1000"}}, "", &filtered); err != nil {
		return vm{}, err
	}
	match, found, err := matchVM(filtered.Items, name)
	if err != nil || found {
		return match, err
	}
	all, err := o.listVMs(ctx)
	if err != nil {
		return vm{}, err
	}
	match, found, err = matchVM(all, name)
	if err != nil || found {
		return match, err
	}
	return vm{}, &vmNotFoundError{Name: name, Available: all}
}

type consoleList struct {
	Items []graphicsConsole `xml:"graphics_console"`
}
type graphicsConsole struct {
	ID       string `xml:"id,attr"`
	Protocol string `xml:"protocol"`
}
type action struct {
	ViewerFile string `xml:"remote_viewer_connection_file"`
}

type ovirtClient struct {
	baseURL  string
	ssoURL   string
	username string
	password string
	token    string
	client   *http.Client
}

func newClient(rawURL, username, password, profile string, caPEM []byte) (*ovirtClient, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("некорректный HTTPS URL API oVirt: %q", rawURL)
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("не удалось загрузить корневой CA-сертификат")
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	login := makeOVirtLogin(username, profile)
	return &ovirtClient{
		baseURL:  strings.TrimRight(parsed.String(), "/"),
		ssoURL:   parsed.Scheme + "://" + parsed.Host + "/ovirt-engine/sso/oauth/token",
		username: login,
		password: password,
		client: &http.Client{
			Transport: transport,
			Timeout:   25 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// oVirt logins are username[@ldap.domain]@profile. An '@' inside an
// LDAP/UPN account name is not a replacement for the oVirt profile.
func makeOVirtLogin(username, profile string) string {
	if strings.HasSuffix(strings.ToLower(username), "@"+strings.ToLower(profile)) {
		return username
	}
	return username + "@" + profile
}

func (o *ovirtClient) close() { o.client.CloseIdleConnections() }

type tokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (o *ovirtClient) authenticate(ctx context.Context) error {
	params := url.Values{
		"grant_type": {"password"},
		"scope":      {"ovirt-app-api"},
		"username":   {o.username},
		"password":   {o.password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.ssoURL, strings.NewReader(params.Encode()))
	if err != nil {
		return fmt.Errorf("ошибка формирования запроса авторизации: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("соединение с SSO oVirt: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return fmt.Errorf("чтение ответа SSO oVirt: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return o.ssoFailure(resp.StatusCode, resp.Header.Get("Content-Type"), data)
	}
	var token tokenResponse
	if err := json.Unmarshal(data, &token); err != nil || token.AccessToken == "" {
		return errors.New("oVirt SSO не вернул access_token в ответе")
	}
	o.token = token.AccessToken
	return nil
}

// ssoFailure extracts only documented OAuth error fields. Never display a raw
// response body: SSO and reverse proxies can include sensitive request data.
func (o *ovirtClient) ssoFailure(status int, contentType string, body []byte) error {
	type oauthError struct {
		Error            string          `json:"error"`
		ErrorDescription string          `json:"error_description"`
		ErrorCode        json.RawMessage `json:"error_code"`
	}
	var details oauthError
	if err := json.Unmarshal(body, &details); err == nil {
		message := strings.TrimSpace(details.Error)
		if len(details.ErrorCode) != 0 && message == "" {
			var codeString string
			if json.Unmarshal(details.ErrorCode, &codeString) == nil {
				message = codeString
			} else {
				var codeNumber json.Number
				if json.Unmarshal(details.ErrorCode, &codeNumber) == nil {
					message = codeNumber.String()
				}
			}
		}
		desc := strings.TrimSpace(details.ErrorDescription)
		if desc != "" && desc != message {
			if message != "" {
				message += ": "
			}
			message += desc
		}
		if message != "" {
			message = strings.Join(strings.Fields(message), " ")
			for _, secret := range []string{o.password, url.QueryEscape(o.password), o.token} {
				if secret != "" {
					message = strings.ReplaceAll(message, secret, "[СКРЫТО]")
				}
			}
			if len([]rune(message)) > 400 {
				message = string([]rune(message)[:400]) + "..."
			}
			return fmt.Errorf("oVirt SSO вернул HTTP %d: %s", status, message)
		}
	}
	if strings.HasPrefix(strings.ToLower(contentType), "text/html") {
		return fmt.Errorf("oVirt SSO вернул HTTP %d с HTML-страницей вместо ответа OAuth (возможна ошибка прокси или неправильный URL)", status)
	}
	return fmt.Errorf("oVirt SSO вернул HTTP %d без диагностических полей error/error_description", status)
}

func (o *ovirtClient) request(ctx context.Context, method, endpoint string, query url.Values, payload string, output any) error {
	if o.token == "" {
		if err := o.authenticate(ctx); err != nil {
			return err
		}
	}
	requestURL := o.baseURL + endpoint
	if len(query) != 0 {
		requestURL += "?" + query.Encode()
	}
	for attempt := 0; attempt < 2; attempt++ {
		var body io.Reader
		if payload != "" {
			body = strings.NewReader(payload)
		}
		req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
		if err != nil {
			return fmt.Errorf("ошибка формирования запроса: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+o.token)
		req.Header.Set("Accept", "application/xml")
		req.Header.Set("Version", "4")
		if payload != "" {
			req.Header.Set("Content-Type", "application/xml")
		}
		resp, err := o.client.Do(req)
		if err != nil {
			return fmt.Errorf("ошибка запроса oVirt (%s %s): %w", method, endpoint, err)
		}
		contents, readErr := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		resp.Body.Close()
		if readErr != nil {
			return fmt.Errorf("ошибка чтения ответа oVirt: %w", readErr)
		}
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			o.token = ""
			if err := o.authenticate(ctx); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			if resp.StatusCode == http.StatusUnauthorized {
				return fmt.Errorf("oVirt отклонил OAuth2-токен (HTTP 401, %s %s). Проверьте права пользователя на REST API", method, endpoint)
			}
			return fmt.Errorf("oVirt вернул HTTP %d (%s %s)", resp.StatusCode, method, endpoint)
		}
		if output != nil {
			if err := xml.Unmarshal(contents, output); err != nil {
				return fmt.Errorf("некорректный XML от oVirt (%s): %w", endpoint, err)
			}
		}
		return nil
	}
	return errors.New("не удалось авторизоваться в oVirt")
}

func (o *ovirtClient) getConnectionFile(ctx context.Context, vmName string, wait time.Duration, progress func(string)) (string, error) {
	current, err := o.resolveVM(ctx, vmName)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(vmName) == "" {
		progress("Выбрана первая доступная ВМ: " + current.Name)
	}
	if current.ID == "" {
		return "", errors.New("сервер не вернул ID виртуальной машины")
	}
	vmPath := "/vms/" + url.PathEscape(current.ID)
	if current.Status == "down" {
		progress("Запускаю виртуальную машину...")
		if err := o.request(ctx, http.MethodPost, vmPath+"/start", nil, "<action/>", nil); err != nil {
			return "", err
		}
	}
	deadline := time.Now().Add(wait)
	for {
		if err := o.request(ctx, http.MethodGet, vmPath, nil, "", &current); err != nil {
			return "", err
		}
		if current.Status == "up" {
			break
		}
		if !time.Now().Before(deadline) {
			return "", fmt.Errorf("таймаут запуска ВМ: текущее состояние %q", current.Status)
		}
		progress("Ожидаю запуска ВМ: " + current.Status)
		timer := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", ctx.Err()
		case <-timer.C:
		}
	}
	var consoles consoleList
	if err := o.request(ctx, http.MethodGet, vmPath+"/graphicsconsoles", nil, "", &consoles); err != nil {
		return "", err
	}
	var consoleID string
	for _, c := range consoles.Items {
		if strings.EqualFold(c.Protocol, "spice") {
			consoleID = c.ID
			break
		}
	}
	if consoleID == "" {
		return "", errors.New("для этой ВМ нет доступной SPICE-консоли")
	}
	var a action
	consolePath := vmPath + "/graphicsconsoles/" + url.PathEscape(consoleID) + "/remoteviewerconnectionfile"
	if err := o.request(ctx, http.MethodPost, consolePath, nil, "<action/>", &a); err != nil {
		return "", err
	}
	// A well-formed .vv file begins with the remote-viewer section header.
	if !bytes.Contains([]byte(a.ViewerFile), []byte("[virt-viewer]")) {
		return "", errors.New("oVirt вернул некорректный файл .vv")
	}
	return a.ViewerFile, nil
}
