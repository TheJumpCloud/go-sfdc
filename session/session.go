// Package session provides handles creation of a Salesforce session
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TheJumpCloud/go-sfdc"
	"github.com/TheJumpCloud/go-sfdc/credentials"
)

// Session is the authentication response.  This is used to generate the
// authroization header for the Salesforce API calls.
type Session struct {
	response *accessTokenResponse
	config   sfdc.Configuration
}

// Clienter interface provides the HTTP client used by the
// the resources.
type Clienter interface {
	Client() *http.Client
}

// InstanceFormatter is the session interface that
// formaters the session instance information used
// by the resources.
//
// InstanceURL will return the Salesforce instance.
//
// AuthorizationHeader will add the authorization to the
// HTTP request's header.
type InstanceFormatter interface {
	InstanceURL() string
	AuthorizationHeader(*http.Request)
	Clienter
}

// ServiceFormatter is the session interface that
// formats the session for service resources.
//
// ServiceURL provides the service URL for resources to
// user.
type ServiceFormatter interface {
	InstanceFormatter
	ServiceURL() string
}

type accessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ID           string `json:"id"`
	InstanceURL  string `json:"instance_url"`
	IssuedAt     string `json:"issued_at"`
	RefreshToken string `json:"refresh_token"`
	Signature    string `json:"signature"`
	TokenType    string `json:"token_type"`
}

const oauthEndpoint = "/services/oauth2/token"

func New(config sfdc.Configuration) *Session {
	return &Session{
		response: &accessTokenResponse{
			AccessToken: config.ExistingSessionInfo.AccessToken,
			InstanceURL: config.ExistingSessionInfo.InstanceURL,
			ID:          config.ExistingSessionInfo.ID,
			IssuedAt:    config.ExistingSessionInfo.IssuedAt,
			Signature:   config.ExistingSessionInfo.Signature,
			TokenType:   config.ExistingSessionInfo.TokenType,
		},
		config: config,
	}
}

// Open is used to authenticate with Salesforce and open a session.  The user will need to
// supply the proper credentials and a HTTP client.
func Open(config sfdc.Configuration) (*Session, error) {
	if config.Credentials == nil {
		return nil, errors.New("session: configuration crendentials can not be nil")
	}
	if config.Client == nil {
		return nil, errors.New("session: configuration client can not be nil")
	}
	if config.Version <= 0 {
		return nil, errors.New("session: configuration version can not be less than zero")
	}

	switch config.Grant {
	case credentials.PasswordGrantType:
		return openPasswordSession(config)

	case credentials.DeviceGrantType:
		return openDeviceSession(config)

	default:
		return nil, fmt.Errorf("session: invalid grant type: %s", config.Grant)
	}
}

func openPasswordSession(config sfdc.Configuration) (*Session, error) {
	request, err := passwordSessionRequest(config.Credentials)

	if err != nil {
		return nil, err
	}

	response, err := passwordSessionResponse(request, config.Client)
	if err != nil {
		return nil, err
	}

	session := &Session{
		response: response,
		config:   config,
	}

	return session, nil
}

func openDeviceSession(config sfdc.Configuration) (*Session, error) {
	if config.ExistingSessionInfo != nil {
		session := &Session{
			response: &accessTokenResponse{
				AccessToken: config.ExistingSessionInfo.AccessToken,
				InstanceURL: config.ExistingSessionInfo.InstanceURL,
				ID:          config.ExistingSessionInfo.ID,
				TokenType:   config.ExistingSessionInfo.TokenType,
				IssuedAt:    config.ExistingSessionInfo.IssuedAt,
				Signature:   config.ExistingSessionInfo.Signature,
			},
			config: config,
		}

		return session, nil
	}

	request, err := buildDeviceAuthenticationFlowInitiationRequest(config.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to build ")
	}

	initResp, err := makeDeviceAuthenticationFlowInitiationRequest(request, config.Client)
	if err != nil {
		return nil, err
	}

	var tokenResp *accessTokenResponse
	var done = make(chan struct{})

	go func() {
		for {
			select {
			case <-time.After(time.Duration(initResp.Interval+1) * time.Second):
				accessTokenReq, err := buildDeviceAuthenticationFlowAccessRequest(config.Credentials, initResp)
				if err != nil {
					log.Fatalf("failed to build device authentication flow access request: %s", err)
				}

				// Make authorization request
				var tokenErrResp *deviceAccessTokenErrorResponse
				if tokenResp, tokenErrResp, err = makeDeviceAuthenticationFlowAccessTokenRequest(accessTokenReq, config.Client); err != nil {
					log.Fatalf("error polling for device access token: %s", err)
				}

				// Success!
				if tokenResp != nil {
					close(done)
					return
				}

				if tokenErrResp != nil && tokenErrResp.Error == AuthorizationPendingErrorCode {
					log.Printf("Authorization pending. Please enter code '%s' at %s to authorize application.", initResp.UserCode, initResp.VerificationURI)
					log.Printf("will attempt to authorize again in %d seconds", initResp.Interval)
				} else {
					log.Printf("unhandled authorization response error: %s: %s", tokenErrResp.Error, tokenErrResp.ErrorDescription)
				}
			}
		}
	}()

	// Wait for successful authorization response.
	<-done

	session := &Session{
		response: tokenResp,
		config:   config,
	}

	return session, nil
}

func buildDeviceAuthenticationFlowInitiationRequest(creds *credentials.Credentials) (*http.Request, error) {
	oauthURL := creds.URL() + oauthEndpoint

	body, err := creds.Retrieve()
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, oauthURL, body)

	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Accept", "application/json")
	return request, nil
}

func makeDeviceAuthenticationFlowInitiationRequest(request *http.Request, client *http.Client) (*deviceAuthenticationFlowInitiationResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session response error: %d %s", response.StatusCode, response.Status)
	}
	decoder := json.NewDecoder(response.Body)
	defer response.Body.Close()

	var sessionResponse deviceAuthenticationFlowInitiationResponse
	err = decoder.Decode(&sessionResponse)
	if err != nil {
		return nil, err
	}

	return &sessionResponse, nil
}

func buildDeviceAuthenticationFlowAccessRequest(creds *credentials.Credentials, authResp *deviceAuthenticationFlowInitiationResponse) (*http.Request, error) {
	oauthURL := creds.URL() + oauthEndpoint

	form := url.Values{}
	form.Add("grant_type", "device")
	form.Add("client_id", creds.ClientID())
	form.Add("code", authResp.DeviceCode)

	if creds.ClientSecret() != "" {
		form.Add("client_secret", creds.ClientSecret())
	}

	request, err := http.NewRequest(http.MethodPost, oauthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}

	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return request, nil
}

func makeDeviceAuthenticationFlowAccessTokenRequest(request *http.Request, client *http.Client) (*accessTokenResponse, *deviceAccessTokenErrorResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}

	switch response.StatusCode {
	case http.StatusBadRequest:
		// Check for an error response.
		var tokenErrResp *deviceAccessTokenErrorResponse
		if err = json.NewDecoder(response.Body).Decode(&tokenErrResp); err != nil {
			return nil, nil, fmt.Errorf("failed to decode error response: %s", err)
		}
		return nil, tokenErrResp, nil

	case http.StatusOK:
		// Check for a successful response.
		var tokenResp *accessTokenResponse
		if err = json.NewDecoder(response.Body).Decode(&tokenResp); err != nil {
			return nil, nil, fmt.Errorf("failed to decode success response: %s", err)
		}
		return tokenResp, nil, nil

	default:
		return nil, nil, fmt.Errorf("device authentication access token request error: %d %s", response.StatusCode, response.Status)
	}
}

func passwordSessionRequest(creds *credentials.Credentials) (*http.Request, error) {

	oauthURL := creds.URL() + oauthEndpoint

	body, err := creds.Retrieve()
	if err != nil {
		return nil, err
	}

	request, err := http.NewRequest(http.MethodPost, oauthURL, body)

	if err != nil {
		return nil, err
	}

	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Accept", "application/json")
	return request, nil
}

func passwordSessionResponse(request *http.Request, client *http.Client) (*accessTokenResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session response error: %d %s", response.StatusCode, response.Status)
	}
	decoder := json.NewDecoder(response.Body)
	defer response.Body.Close()

	var sessionResponse accessTokenResponse
	err = decoder.Decode(&sessionResponse)
	if err != nil {
		return nil, err
	}

	return &sessionResponse, nil
}

func (session *Session) AccessToken() string {
	return session.response.AccessToken
}

func (session *Session) RefreshToken() string {
	return session.response.RefreshToken
}

func (session *Session) TokenType() string {
	return session.response.TokenType
}

func (session *Session) ID() string {
	return session.response.ID
}

func (session *Session) IssuedAt() string {
	return session.response.IssuedAt
}

func (session *Session) Signature() string {
	return session.response.Signature
}

// InstanceURL will retuern the Salesforce instance
// from the session authentication.
func (session *Session) InstanceURL() string {
	return session.response.InstanceURL
}

// ServiceURL will return the Salesforce instance for the
// service URL.
func (session *Session) ServiceURL() string {
	return fmt.Sprintf("%s/services/data/v%d.0", session.response.InstanceURL, session.config.Version)
}

// AuthorizationHeader will add the authorization to the
// HTTP request's header.
func (session *Session) AuthorizationHeader(request *http.Request) {
	auth := fmt.Sprintf("%s %s", session.response.TokenType, session.response.AccessToken)
	request.Header.Add("Authorization", auth)
}

// Client returns the HTTP client to be used in APIs calls.
func (session *Session) Client() *http.Client {
	return session.config.Client
}
