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
	URL          string
}

type deviceProvider struct {
	creds DeviceCredentials
}

// NewDeviceCredentials will create a crendential with the device credentials.
func NewDeviceCredentials(creds DeviceCredentials) (*Credentials, error) {
	// if err := validatePasswordCredentails(creds); err != nil {
	// 	return nil, err
	// }
	return &Credentials{
		provider: &deviceProvider{
			creds: creds,
		},
	}, nil
}

func (provider *deviceProvider) Retrieve() (io.Reader, error) {
	form := url.Values{}

	form.Add("grant_type", string(DeviceGrantType))
	form.Add("client_id", provider.creds.ClientID)
	form.Add("code", provider.creds.Code)

	if provider.creds.ClientSecret != "" {
		form.Add("client_secret", provider.creds.ClientSecret)
	}

	return strings.NewReader(form.Encode()), nil
}

func (provider *deviceProvider) URL() string {
	return provider.creds.URL
}
