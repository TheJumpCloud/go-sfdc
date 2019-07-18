// Package session provides handles creation of a Salesforce session.
// Device authorization follows the OAuth 2.0 Device Authentication flow as outlined at
// https://help.salesforce.com/articleView?id=remoteaccess_oauth_device_flow.htm&type=5
package session

// TODO(@rmulley): Add comments to each error.
const (
	AccessDeniedErrorCode         = "access_denied"
	AuthorizationPendingErrorCode = "authorization_pending"
	InvalidGrantErrorCode         = "invalid_grant"
	InvalidRequestErrorCode       = "invalid_request"
	ServerErrorErrorCode          = "server_error"
	SlowDownErrorCode             = "slow_down"
)

type deviceAuthenticationFlowInitiationRequest struct {
	ClientID     string `json:"client_id"`
	ResponseType string `json:"response_type"`
	Scope        string `json:"scope,omitempty"`
}

type deviceAuthenticationFlowInitiationResponse struct {
	DeviceCode      string `json:"device_code"`
	Interval        int64  `json:"interval"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
}

type deviceAccessTokenRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	Code         string `json:"code"`
	Grant        string `json:"grant_type"`
}

type deviceAccessTokenResponse struct {
	AccessToken  string `json:"access_token"`
	ID           string `json:"id"`
	InstanceURL  string `json:"instance_url"`
	IssuedAt     string `json:"issued_at"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
	Signature    string `json:"signature"`
	TokenType    string `json:"token_type"`
}

type deviceAccessTokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
