package credentials

import (
	"io"
	"net/url"
	"strings"
)

type DeviceCredentials struct {
	ClientID     string
	ClientSecret string
	Code         string
	Scopes       []string
	URL          string
}

type deviceProvider struct {
	creds DeviceCredentials
}

// NewDeviceCredentials will create a crendential with the device credentials.
func NewDeviceCredentials(creds DeviceCredentials) (*Credentials, error) {
	return &Credentials{
		provider: &deviceProvider{
			creds: creds,
		},
	}, nil
}

func (provider *deviceProvider) ClientID() string {
	return provider.creds.ClientID
}

func (provider *deviceProvider) ClientSecret() string {
	return provider.creds.ClientSecret
}

func (provider *deviceProvider) Retrieve() (io.Reader, error) {
	form := url.Values{}

	form.Add("response_type", "device_code")
	form.Add("client_id", provider.creds.ClientID)

	if provider.creds.ClientSecret != "" {
		form.Add("client_secret", provider.creds.ClientSecret)
	}

	for _, scope := range provider.creds.Scopes {
		form.Add("scope", scope)
	}

	return strings.NewReader(form.Encode()), nil
}

func (provider *deviceProvider) URL() string {
	return provider.creds.URL
}
