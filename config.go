package sfdc

import (
	"net/http"

	"github.com/g8rswimmer/go-sfdc/credentials"
)

// Configuration is the structure for goforce sessions.
//
// Credentials is the credentials that will be used to form a session.
//
// Client is the HTTP client that will be used.
//
// Version is the Salesforce version for the APIs.
type Configuration struct {
	Credentials *credentials.Credentials
	Client      *http.Client
	Grant       credentials.GrantType
	Version     int

	ExistingSessionInfo *SessionInfo
}

type SessionInfo struct {
	AccessToken string `json:"access_token"`
	InstanceURL string `json:"instance_url"`
	ID          string `json:"id"`
	TokenType   string `json:"token_type"`
	IssuedAt    string `json:"issued_at"`
	Signature   string `json:"signature"`
}
