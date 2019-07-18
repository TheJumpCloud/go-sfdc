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

func (provider *deviceProvider) Retrieve() (io.Reader, error) {
	form := url.Values{}

	form.Add("grant_type", string(deviceGrantType))
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
