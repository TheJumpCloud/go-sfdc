// Package session provides handles creation of a Salesforce session
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/TheJumpCloud/go-sfdc"
	"github.com/TheJumpCloud/go-sfdc/credentials"
)

// Session is the authentication response.  This is used to generate the
// authroization header for the Salesforce API calls.
type Session struct {
	response *sessionPasswordResponse
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

type sessionPasswordResponse struct {
	AccessToken string `json:"access_token"`
	InstanceURL string `json:"instance_url"`
	ID          string `json:"id"`
	TokenType   string `json:"token_type"`
	IssuedAt    string `json:"issued_at"`
	Signature   string `json:"signature"`
}

const oauthEndpoint = "/services/oauth2/token"

// Open is used to authenticate with Salesforce and open a session.  The user will need to
// supply the proper credentails and a HTTP client.
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
		return nil, fmt.Errorf("session: invalid grant type %s", config.Grant)
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
	request, err := buildDeviceAuthenticationFlowInitiationRequest(config.Credentials)
	if err != nil {
		return nil, fmt.Errorf("failed to ")
	}

	initResp, err := makeDeviceAuthenticationFlowInitiationRequest(request, config.Client)
	if err != nil {
		return nil, err
	}

	accessTokenReq, err := buildDeviceAuthenticationFlowAccessRequest(config.Credentials, initResp)
	if err != nil {
		return nil, err
	}

	var tokenResp *deviceAccessTokenResponse
	for {
		select {
		case <-time.After(time.Duration(initResp.Interval + 1)):
			// TODO(@rmulley): Make request
			var tokenErrResp *deviceAccessTokenErrorResponse
			if tokenResp, tokenErrResp, err = makeDeviceAuthenticationFlowAccessTokenRequest(accessTokenReq, config.Client); err != nil {
				log.Fatalf("Error polling for device access token: %s", err)
			}

			// Success!
			if tokenResp != nil {
				break
			}

			if tokenErrResp.Error == AuthorizationPendingErrorCode {
				log.Printf("Authorization pending. Please enter code '%s' at %s to authorize application", initResp.UserCode, initResp.VerificationURI)
				log.Printf("Will attempt to authorize again in %d seconds", initResp.Interval)
			} else {
				log.Fatalf("Failed to retrieve access token: %s: %s", tokenErrResp.Error, tokenErrResp.ErrorDescription)
			}
		}
	}

	log.Fatalf("SUCCESS: %+v", tokenResp)

	session := &Session{
		// response: tokenResp,
		config: config,
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

func makeDeviceAuthenticationFlowAccessTokenRequest(request *http.Request, client *http.Client) (*deviceAccessTokenResponse, *deviceAccessTokenErrorResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("session response error: %d %s", response.StatusCode, response.Status)
	}
	decoder := json.NewDecoder(response.Body)
	defer response.Body.Close()

	// Check for an error response first.
	var errResponse *deviceAccessTokenErrorResponse
	if err = decoder.Decode(&errResponse); err != nil {
		return nil, errResponse, nil
	}

	// Check for a successful response.
	var tokenResp *deviceAccessTokenResponse
	err = decoder.Decode(&tokenResp)
	if err != nil {
		return nil, nil, err
	}

	return tokenResp, nil, nil
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

func passwordSessionResponse(request *http.Request, client *http.Client) (*sessionPasswordResponse, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("session response error: %d %s", response.StatusCode, response.Status)
	}
	decoder := json.NewDecoder(response.Body)
	defer response.Body.Close()

	var sessionResponse sessionPasswordResponse
	err = decoder.Decode(&sessionResponse)
	if err != nil {
		return nil, err
	}

	return &sessionResponse, nil
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
