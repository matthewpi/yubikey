//
// Copyright (c) 2019 Matthew Penner <me@matthewp.io>
//
// This repository is licensed under the MIT License.
// https://github.com/matthewpi/yubikey/blob/develop/LICENSE.md
//

package yubikey

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalidLength = errors.New("otp: invalid length")
	ErrInvalidOTP    = errors.New("otp: invalid format or contains invalid characters")
	ErrMismatchOTP   = errors.New("validate: mismatched otp")
	ErrMismatchNonce = errors.New("validate: mismatched nonce")
	ErrStatus        = errors.New("validate: non-OK status received")

	dvorakToQwerty = strings.NewReplacer(
		"j", "c", "x", "b", "e", "d", ".", "e", "u", "f", "i", "g", "d", "h", "c", "i",
		"h", "j", "t", "k", "n", "l", "b", "n", "p", "r", "y", "t", "g", "u", "k", "v",
		"J", "C", "X", "B", "E", "D", ".", "E", "U", "F", "I", "G", "D", "H", "C", "I",
		"H", "J", "T", "K", "N", "L", "B", "N", "P", "R", "Y", "T", "G", "U", "K", "V",
	)
	matchDvorak = regexp.MustCompile(`^[jxe.uidchtnbpygkJXEUIDCHTNBPYGK]{32,48}$`)
	matchQwerty = regexp.MustCompile(`^[cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{32,48}$`)
)

// Client .
type Client struct {
	http     *http.Client
	ClientID string
	Servers  []string
}

// New creates a new Yubikey client for validating Yubikey OTPs.
func New(clientID string, servers []string) *Client {
	client := &Client{
		http:     &http.Client{},
		ClientID: clientID,
	}

	if servers == nil {
		client.Servers = []string{"api.yubico.com", "api2.yubico.com", "api3.yubico.com", "api4.yubico.com", "api5.yubico.com"}
	} else {
		client.Servers = servers
	}

	return client
}

// IsValidOTP checks if the given OTP is valid according to the Yubikey OTP specification.
// If the OTP is invalid, this method will return an error;
// If the OTP is valid, this the method will return nil.
func (client *Client) IsValidOTP(otp string) error {
	// TODO: Wrap regex in timeouts because it's regex..

	if len(otp) < 32 || len(otp) > 48 {
		return ErrInvalidLength
	}

	// Convert DVORAK to QWERTY
	if matchDvorak.MatchString(otp) {
		otp = dvorakToQwerty.Replace(otp)
	}

	// Check if the OTP is now a valid OTP according to the Yubikey OTP spec.
	if !matchQwerty.MatchString(otp) {
		return ErrInvalidOTP
	}

	// All checks passed, no errors.
	return nil
}

// GetIdentity gets the identity section of an OTP.
func (client *Client) GetIdentity(otp string) string {
	if len(otp) < 33 {
		return ""
	}

	// Cut the last 32 characters off of the OTP to retrieve the identity of the Yubikey.
	otp = otp[:len(otp)-32]
	return otp
}

// Validate validates the given OTP against the configured servers.
func (client *Client) Validate(otp string) error {
	// Get a nonce for the OTP.
	nonce := client.nonce(otp)

	// Create a channel to retrieve only the first API response.
	// It might make sense to capture all of them to be safe, but that's a problem for tomorrow.
	done := make(chan map[string]string, 0)

	// Make a request to all the configured APIs for redundancy reasons.
	for _, server := range client.Servers {
		go client.api(done, server, otp, nonce)
	}

	// Get the first valid response from all of the API requests.
	responseData := <-done
	fmt.Printf("%s: %s\n", responseData["_server"], responseData["status"])

	// Check if the OTPs are mismatched.
	if otp != responseData["otp"] {
		return ErrMismatchOTP
	}

	// Check if the Nonces are mismatched.
	if nonce != responseData["nonce"] {
		return ErrMismatchNonce
	}

	// Check if the status is not OK.
	if responseData["status"] != "OK" {
		return ErrStatus
	}

	return nil
}

// api makes a GET request using the specified settings.
func (client *Client) api(done chan map[string]string, server string, otp string, nonce string) {
	// Create a new HTTP request.
	req, err := http.NewRequest(
		"GET",
		fmt.Sprintf(
			"https://%s/wsapi/2.0/verify?id=%s&otp=%s&nonce=%s&sl=secure",
			server,
			client.ClientID,
			otp,
			nonce,
		),
		nil,
	)
	if err != nil {
		return
	}

	// Set the User-Agent header.
	req.Header.Set("User-Agent", "github.com/matthewpi/yubikey")

	// Run the http request.
	res, err := client.http.Do(req)
	if err != nil {
		return
	}

	// Close the request body once we are done.
	defer func() {
		_ = res.Body.Close()
	}()

	// Read the request body.
	response, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	// Parse the response data.
	sections := strings.Split(string(response), "\n")
	responseData := map[string]string{}

	// Loop through the sections in the response body.
	for _, section := range sections {
		line := strings.SplitN(section, "=", 2)
		if len(line) == 2 {
			responseData[line[0]] = strings.Trim(line[1], "\n\r")
		}
	}

	// REPLAYED_REQUEST means that another API request is also trying to validate the OTP simultaneously
	// so don't send this response's data to the channel and instead wait for the other request.
	if responseData["status"] == "REPLAYED_REQUEST" {
		return
	}

	// Send the response to the channel unless it is full.
	responseData["_server"] = server
	select {
	case done <- responseData:
	default:
		return
	}
}

// nonce generates a nonce for the given OTP.
func (client *Client) nonce(otp string) string {
	rand.Seed(time.Now().UnixNano())
	nonce := make([]rune, 40)
	for i := 0; i < 40; i++ {
		c := rand.Intn(35)

		if c < 10 {
			c += 48 // numbers (0-9) (0+48 == 48 == '0', 9+48 == 57 == '9')
		} else {
			c += 87 // lower case alphabets (a-z) (10+87 == 97 == 'a', 35+87 == 122 = 'z')
		}

		nonce[i] = rune(c)
	}

	return string(nonce)
}
