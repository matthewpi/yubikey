//
// Copyright (c) 2019 Matthew Penner <me@matthewp.io>
//
// This repository is licensed under the MIT License.
// https://github.com/matthewpi/yubikey/blob/develop/LICENSE.md
//

package yubikey

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var client *Client

func TestNew(t *testing.T) {
	assert := assert.New(t)

	// Create a new client
	client = New("", nil)

	// Assertions
	assert.NotEqual(nil, client, "Client should not be nil.")
	assert.NotEqual(nil, client.ClientID, "Client#ClientID should not be nil.")
	assert.NotEqual(nil, client.Servers, "Client#Servers should not be nil.")
}

func TestNew_WithServers(t *testing.T) {
	assert := assert.New(t)

	// Create a new client with the specified servers.
	servers := []string{"api.yubico.com", "api3.yubico.com", "api5.yubico.com"}
	client = New("", servers)

	// Assertions
	assert.NotEqual(nil, client, "Client should not be nil.")
	assert.NotEqual(nil, client.ClientID, "Client#ClientID should not be nil.")
	assert.Equal(servers, client.Servers, "Client#Servers should be set to the custom ones provided.")
}

func TestClient_IsValidOTP(t *testing.T) {
	assert := assert.New(t)

	// Assertions
	assert.Equal(ErrInvalidLength, client.IsValidOTP("not 32-48 char string"))
	assert.Equal(ErrInvalidLength, client.IsValidOTP("definitely a string that is longer than 48 characters just because we can!"))
	assert.Equal(ErrInvalidOTP, client.IsValidOTP("this string is definitely not an otp"))
	assert.Equal(nil, client.IsValidOTP("ccccccidlfvvvuefkdgcilrjcfffijigdhrbvngfgelb"))

}

func TestClient_GetIdentity(t *testing.T) {
	assert := assert.New(t)

	// Assertions
	assert.Equal("", client.GetIdentity("string that would cause panic"))
	assert.Equal("ccccccidlfvv", client.GetIdentity("ccccccidlfvvvuefkdgcilrjcfffijigdhrbvngfgelb"))
}

// TODO: TestClient_Validate

func TestClient_nonce(t *testing.T) {
	assert := assert.New(t)

	// Assertions
	assert.Equal(40, len(client.nonce("ccccccidlfvvvuefkdgcilrjcfffijigdhrbvngfgelb")))
}
