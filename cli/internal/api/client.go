// Package api is a thin HTTP client for the OpenCM REST API.
// M1 replaces the hand-written request types with a client generated from
// server/openapi.yaml (oapi-codegen); the transport/error handling stays here.
package api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const BasePath = "/api/v1"

type Client struct {
	Server string
	Token  string
	HTTP   *http.Client
}

func New(server, token string, insecure bool) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // explicit opt-in
	}
	return &Client{
		Server: strings.TrimRight(server, "/"),
		Token:  token,
		HTTP:   &http.Client{Timeout: 60 * time.Second, Transport: tr},
	}
}

// Error is the server's error envelope plus the HTTP status.
type Error struct {
	Status  int
	Code    string          `json:"code"`
	Message string          `json:"message"`
	Details json.RawMessage `json:"details,omitempty"`
}

func (e *Error) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("HTTP %d", e.Status)
	}
	return fmt.Sprintf("%s (HTTP %d)", e.Message, e.Status)
}

// Raw performs a GET-style request and returns the response body unparsed
// (for file downloads). The caller must close it.
func (c *Client) Raw(method, path string, query url.Values) (io.ReadCloser, error) {
	u := c.Server + BasePath + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(method, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "opencm-cli")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := *c.HTTP
	hc.Timeout = 10 * time.Minute
	res, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode >= 400 {
		defer res.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
		var env struct {
			Error Error `json:"error"`
		}
		_ = json.Unmarshal(data, &env)
		env.Error.Status = res.StatusCode
		return nil, &env.Error
	}
	return res.Body, nil
}

// Upload streams body as application/octet-stream (PUT) and decodes the JSON response into out.
func (c *Client) Upload(path string, query url.Values, body io.Reader, size int64, out any) error {
	u := c.Server + BasePath + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodPut, u, body)
	if err != nil {
		return err
	}
	req.ContentLength = size
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "opencm-cli")
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	hc := *c.HTTP
	hc.Timeout = 0 // large installers: no overall timeout
	res, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 400 {
		var env struct {
			Error Error `json:"error"`
		}
		_ = json.Unmarshal(data, &env)
		env.Error.Status = res.StatusCode
		return &env.Error
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Do performs a request against BasePath+path. body (if non-nil) is sent as JSON,
// the response is decoded into out (if non-nil).
func (c *Client) Do(method, path string, query url.Values, body, out any) error {
	u := c.Server + BasePath + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "opencm-cli")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 400 {
		var env struct {
			Error Error `json:"error"`
		}
		_ = json.Unmarshal(data, &env)
		env.Error.Status = res.StatusCode
		return &env.Error
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
