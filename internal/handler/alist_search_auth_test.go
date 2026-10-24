package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/alist-encrypt-go/internal/config"
	"github.com/alist-encrypt-go/shared/encryptcore"
)

func TestHandleFsSearchPreservesCallerAuthAcrossPaths(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		parent        string
		keyword       string
		scope         int
		failureBody   string
		failureStatus int
		wantLists     []string
		wantSearch    bool
	}{
		{
			name: "recursive raw upstream JWT", authorization: "upstream-jwt",
			parent: "/encrypt", keyword: "sample", scope: 2,
			wantLists: []string{"/encrypt", "/encrypt/child"},
		},
		{
			name: "recursive bearer forwarded verbatim", authorization: "Bearer upstream-jwt",
			parent: "/encrypt", keyword: "sample", scope: 2,
			wantLists: []string{"/encrypt", "/encrypt/child"},
		},
		{
			name: "root search encrypted roots", authorization: "upstream-jwt",
			parent: "/", keyword: "sample", scope: 2,
			wantLists: []string{"/encrypt", "/encrypt/child"},
		},
		{
			name: "direct upstream search", authorization: "upstream-jwt",
			parent: "/", wantSearch: true,
		},
		{
			name: "recursive failure fallback retains caller", authorization: "upstream-jwt",
			parent: "/encrypt", keyword: "sample", wantLists: []string{"/encrypt"}, wantSearch: true,
			failureStatus: http.StatusOK,
			failureBody:   `{"code":500,"message":"listing unavailable","data":null}`,
		},
		{
			name: "invalid upstream token is not replaced", authorization: "invalid-upstream-jwt",
			parent: "/encrypt", keyword: "sample", wantLists: []string{"/encrypt"}, wantSearch: true,
			failureStatus: http.StatusOK,
			failureBody:   `{"code":401,"message":"token is invalidated","data":null}`,
		},
		{
			name:   "local JWT only stays anonymous despite scan credentials",
			parent: "/encrypt", keyword: "sample", wantLists: []string{"/encrypt"}, wantSearch: true,
			failureStatus: http.StatusOK,
			failureBody:   `{"code":401,"message":"Guest user is disabled, login please","data":null}`,
		},
		{
			name: "HTTP unauthorized is preserved", authorization: "expired-upstream-jwt",
			parent: "/", wantSearch: true,
			failureStatus: http.StatusUnauthorized,
			failureBody:   `{"code":401,"message":"token is expired","data":null}`,
		},
		{
			name: "upstream permission denial is preserved", authorization: "restricted-upstream-jwt",
			parent: "/", wantSearch: true,
			failureStatus: http.StatusOK,
			failureBody:   `{"code":403,"message":"permission denied","data":null}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passwd := &config.PasswdInfo{
				Password: "testpass", EncType: "aesctr", Enable: true, EncName: true,
				EncPath: []string{"/encrypt/*"},
			}
			converter := encryption.NewFileNameConverter(passwd.Password, passwd.EncType, passwd.EncSuffix)
			leafRaw := converter.ToRealName("sample_video.mp4")
			var listPaths []string
			searches := 0
			upstream := newSocketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != tt.authorization {
					t.Errorf("%s Authorization = %q, want %q", r.URL.Path, got, tt.authorization)
				}
				for _, header := range []string{"Authorizetoken", "X-User-Token"} {
					if r.Header.Get(header) != "" {
						t.Errorf("%s leaked local-only header %s", r.URL.Path, header)
					}
				}
				if got := r.Header.Get("Cookie"); got != "upstream-session=test" {
					t.Errorf("%s Cookie = %q, want explicit caller cookie", r.URL.Path, got)
				}
				switch r.URL.Path {
				case "/api/fs/list":
					var body struct {
						Path string `json:"path"`
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Errorf("decode list request: %v", err)
					}
					listPaths = append(listPaths, body.Path)
					if tt.failureBody != "" {
						w.Header().Set("Content-Type", "application/json")
						w.WriteHeader(tt.failureStatus)
						_, _ = w.Write([]byte(tt.failureBody))
						return
					}
					content := []interface{}{}
					switch body.Path {
					case "/encrypt":
						content = append(content, map[string]interface{}{"name": "child", "is_dir": true})
					case "/encrypt/child":
						content = append(content, map[string]interface{}{"name": leafRaw, "is_dir": false})
					default:
						t.Errorf("unexpected list path %q", body.Path)
					}
					writeJSONResponse(w, map[string]interface{}{
						"code": 200, "message": "success",
						"data": map[string]interface{}{"content": content, "total": len(content)},
					})
				case "/api/fs/search":
					searches++
					w.Header().Set("Content-Type", "application/json")
					if tt.failureBody != "" {
						w.WriteHeader(tt.failureStatus)
						_, _ = w.Write([]byte(tt.failureBody))
						return
					}
					writeJSONResponse(w, map[string]interface{}{
						"code": 200, "message": "success",
						"data": map[string]interface{}{"content": []interface{}{}, "total": 0},
					})
				default:
					t.Errorf("unexpected upstream route %s; must not log in with configured scan credentials", r.URL.Path)
					w.WriteHeader(http.StatusInternalServerError)
				}
			}))
			defer upstream.Close()
			h, _ := newTestAlistHandler(t, upstream.URL, passwd)
			// Configured scan credentials must never elevate a public search caller.
			h.cfg.AlistServer.ScanAuthHeader = "scan-admin-token"
			h.cfg.AlistServer.ScanUsername = "scan-owner"
			h.cfg.AlistServer.ScanPassword = "scan-password"
			payload, err := json.Marshal(fsSearchRequest{
				Parent: tt.parent, Keywords: tt.keyword, Scope: tt.scope, Page: 1, PerPage: 20,
			})
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/api/fs/search", strings.NewReader(string(payload)))
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			req.Header.Set("Authorizetoken", "local-management-jwt")
			req.Header.Set("X-User-Token", "local-user-token")
			req.Header.Set("Cookie", "upstream-session=test")
			rec := httptest.NewRecorder()
			h.HandleFsSearch(rec, req)

			wantStatus := http.StatusOK
			if tt.failureStatus != 0 {
				wantStatus = tt.failureStatus
			}
			if rec.Code != wantStatus {
				t.Errorf("HTTP status = %d, want %d", rec.Code, wantStatus)
			}
			if tt.failureBody != "" {
				if got := rec.Body.String(); got != tt.failureBody {
					t.Errorf("upstream failure changed: got %s, want %s", got, tt.failureBody)
				}
			} else {
				var response struct {
					Code int `json:"code"`
					Data struct {
						Total int `json:"total"`
					} `json:"data"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
					t.Fatal(err)
				}
				wantTotal := 1
				if tt.wantSearch {
					wantTotal = 0
				}
				if response.Code != 200 || response.Data.Total != wantTotal {
					t.Errorf("search response code=%d total=%d, want code=200 total=%d", response.Code, response.Data.Total, wantTotal)
				}
			}
			if !reflect.DeepEqual(listPaths, tt.wantLists) {
				t.Errorf("list paths = %v, want %v", listPaths, tt.wantLists)
			}
			wantSearches := 0
			if tt.wantSearch {
				wantSearches = 1
			}
			if searches != wantSearches {
				t.Errorf("upstream searches = %d, want %d", searches, wantSearches)
			}
		})
	}
}
