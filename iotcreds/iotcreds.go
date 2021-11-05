package iotcreds

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"net/http"
	"strings"
	"time"
)

func Retrieve(endpoint, roleAlias, thingName string, cert tls.Certificate) (*Credentials, error) {
	u := fmt.Sprintf("%s/role-aliases/%s/credentials", strings.TrimSuffix(endpoint, "/"), roleAlias)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("x-amzn-iot-thingname", thingName)

	c := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		},
	}

	resp, err := c.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if resp.StatusCode != 200 {
		return nil, errors.Errorf("unexpected status code: %d %s", resp.StatusCode, resp.Status)
	}

	iotCreds := iotCredentialsResponse{}
	err = json.NewDecoder(resp.Body).Decode(&iotCreds)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return &iotCreds.Credentials, nil
}

type Credentials struct {
	AccessKeyId     string    `json:"accessKeyId"`
	SecretAccessKey string    `json:"secretAccessKey"`
	SessionToken    string    `json:"sessionToken"`
	Expiration      time.Time `json:"expiration"`
}

type iotCredentialsResponse struct {
	Credentials Credentials `json:"credentials"`
}

