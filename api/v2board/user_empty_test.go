package panel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

func TestGetUserListDistinguishesEmpty200FromNotModified(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        func(t *testing.T) []byte
	}{
		{
			name:        "json",
			contentType: "application/json",
			body: func(_ *testing.T) []byte {
				return []byte(`{"users":[]}`)
			},
		},
		{
			name:        "msgpack",
			contentType: "application/x-msgpack",
			body: func(t *testing.T) []byte {
				body, err := msgpack.Marshal(UserListBody{Users: []UserInfo{}})
				if err != nil {
					t.Fatalf("msgpack.Marshal: %v", err)
				}
				return body
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requestCount++
				if requestCount == 2 {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				w.Header().Set("Content-Type", tt.contentType)
				w.Header().Set("ETag", `"empty"`)
				_, _ = w.Write(tt.body(t))
			}))
			defer server.Close()

			client := newPanelTestClient(t, server.URL)
			users, err := client.GetUserList(context.Background())
			if err != nil {
				t.Fatalf("first GetUserList: %v", err)
			}
			if users == nil || len(users) != 0 {
				t.Fatalf("200 empty list = %#v, want non-nil empty slice", users)
			}

			users, err = client.GetUserList(context.Background())
			if err != nil {
				t.Fatalf("second GetUserList: %v", err)
			}
			if users != nil {
				t.Fatalf("304 list = %#v, want nil", users)
			}
		})
	}
}

// An error response must not be decoded into an empty user list: callers treat
// a non-nil empty list as "remove every credential on this node".
func TestGetUserListRejectsErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"users":[]}`))
	}))
	defer server.Close()

	client := newPanelTestClient(t, server.URL)
	users, err := client.GetUserList(context.Background())
	if err == nil {
		t.Fatalf("500 response returned %#v without an error", users)
	}
	if users != nil {
		t.Fatalf("500 response returned a user list: %#v", users)
	}
}
