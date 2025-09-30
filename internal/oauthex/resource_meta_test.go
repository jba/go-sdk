// Copyright 2025 The Go MCP SDK Authors. All rights reserved.
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package oauthex

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func Test_getPRM(t *testing.T) {
	ctx := context.Background()
	const wantResource = "https://resource.example.com"

	prmOK := &ProtectedResourceMetadata{
		Resource:             wantResource,
		AuthorizationServers: []string{"https://as.example.com"},
	}
	prmOKJSON, err := json.Marshal(prmOK)
	if err != nil {
		t.Fatal(err)
	}

	prmMismatchedResource := &ProtectedResourceMetadata{
		Resource: "https://wrong.example.com",
	}
	prmMismatchedResourceJSON, err := json.Marshal(prmMismatchedResource)
	if err != nil {
		t.Fatal(err)
	}

	prmBadAuthServer := &ProtectedResourceMetadata{
		Resource:             wantResource,
		AuthorizationServers: []string{"javascript:alert(1)"},
	}
	prmBadAuthServerJSON, err := json.Marshal(prmBadAuthServer)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			w.Header().Set("Content-Type", "application/json")
			w.Write(prmOKJSON)
		case "/mismatched-resource":
			w.Header().Set("Content-Type", "application/json")
			w.Write(prmMismatchedResourceJSON)
		case "/bad-auth-server":
			w.Header().Set("Content-Type", "application/json")
			w.Write(prmBadAuthServerJSON)
		case "/bad-status":
			http.Error(w, "not found", http.StatusNotFound)
		case "/bad-content-type":
			w.Header().Set("Content-Type", "text/plain")
			w.Write([]byte("not json"))
		case "/bad-json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not-json"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tests := []struct {
		name         string
		purl         string
		wantResource string
		client       *http.Client
		want         *ProtectedResourceMetadata
		wantErr      string
	}{
		{
			name:         "non-https url",
			purl:         "http://example.com",
			wantResource: wantResource,
			wantErr:      `resource URL "http://example.com" does not use HTTPS`,
		},
		{
			name:         "http get error",
			purl:         "https://localhost:0", // Invalid port to cause connection error
			wantResource: wantResource,
			wantErr:      `Get "https://localhost:0": dial tcp`,
		},
		{
			name:         "bad status code",
			purl:         server.URL + "/bad-status",
			wantResource: wantResource,
			client:       server.Client(),
			wantErr:      "bad status 404 Not Found",
		},
		{
			name:         "bad content type",
			purl:         server.URL + "/bad-content-type",
			wantResource: wantResource,
			client:       server.Client(),
			wantErr:      `bad content type "text/plain"`,
		},
		{
			name:         "bad json",
			purl:         server.URL + "/bad-json",
			wantResource: wantResource,
			client:       server.Client(),
			wantErr:      "invalid character 'o' in literal null (expecting 'u')",
		},
		{
			name:         "mismatched resource",
			purl:         server.URL + "/mismatched-resource",
			wantResource: wantResource,
			client:       server.Client(),
			wantErr:      `got metadata resource "https://wrong.example.com", want "https://resource.example.com"`,
		},
		{
			name:         "bad auth server url scheme",
			purl:         server.URL + "/bad-auth-server",
			wantResource: wantResource,
			client:       server.Client(),
			wantErr:      `URL has disallowed scheme "javascript"`,
		},
		{
			name:         "success",
			purl:         server.URL + "/ok",
			wantResource: wantResource,
			client:       server.Client(),
			want:         prmOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getPRM(ctx, tt.purl, tt.client, tt.wantResource)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("getPRM() error = nil, wantErr %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("getPRM() error = %q, want to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("getPRM() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getPRM() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetProtectedResourceMetadataFromHeader(t *testing.T) {
	ctx := context.Background()

	prmOK := &ProtectedResourceMetadata{
		Resource: "https://resource.example.com/prm",
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The resource URL in prmOK doesn't match the server URL, so we need to adjust it.
		// prmOK.Resource = server.URL + "/prm"
		prmOKJSON, _ := json.Marshal(prmOK)

		if r.URL.Path == "/prm" {
			w.Header().Set("Content-Type", "application/json")
			w.Write(prmOKJSON)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	httpsURL := server.URL + "/prm"
	prmOK.Resource = server.URL + "/prm"

	// The expected resource must match the dynamic URL of the test server.
	wantPRM := &ProtectedResourceMetadata{
		Resource: httpsURL,
	}

	tests := []struct {
		name    string
		header  http.Header
		client  *http.Client
		want    *ProtectedResourceMetadata
		wantErr string
	}{
		{
			name:   "no www-authenticate header",
			header: http.Header{},
			want:   nil,
		},
		{
			name: "empty www-authenticate header",
			header: http.Header{
				"Www-Authenticate": []string{},
			},
			want: nil,
		},
		{
			name: "no resource_metadata parameter",
			header: http.Header{
				"Www-Authenticate": []string{`Bearer realm="example.com"`},
			},
			want: nil,
		},
		{
			name: "success",
			header: http.Header{
				"Www-Authenticate": []string{fmt.Sprintf(`Bearer resource_metadata="%s"`, httpsURL)},
			},
			client: server.Client(),
			want:   wantPRM,
		},
		{
			name: "getPRM fails with non-https url",
			header: http.Header{
				"Www-Authenticate": []string{`Bearer resource_metadata="http://insecure.com"`},
			},
			client:  server.Client(),
			wantErr: `resource URL "http://insecure.com" does not use HTTPS`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetProtectedResourceMetadataFromHeader(ctx, tt.header, tt.client)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("GetProtectedResourceMetadataFromHeader() error = nil, wantErr %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("GetProtectedResourceMetadataFromHeader() error = %q, want to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetProtectedResourceMetadataFromHeader() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetProtectedResourceMetadataFromHeader() got = %+v, want %+v", got, tt.want)
			}
		})
	}
}
