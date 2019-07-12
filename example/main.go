//
// Copyright (c) 2019 Matthew Penner <me@matthewp.io>
//
// This repository is licensed under the MIT License.
// https://github.com/matthewpi/yubikey/blob/develop/LICENSE.md
//

package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/matthewpi/yubikey"
	"os"
	"strings"
)

func main() {
	// Add a command line flag for a Yubico clientId
	clientID := flag.String("clientId", "", "#####")
	flag.Parse()

	client := yubikey.New(*clientID, nil)

	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Ready!")
	for {
		fmt.Printf("\nEnter OTP: ")
		text, _ := reader.ReadString('\n')
		text = strings.Replace(text, "\n", "", -1)

		// Make sure the OTP is valid.
		if err := client.IsValidOTP(text); err != nil {
			fmt.Printf("Invalid OTP: %s\n", err.Error())
			continue
		}

		// Validate the OTP.
		if err := client.Validate(text); err != nil {
			fmt.Printf("Validation Error: %s\n", err.Error())
			continue
		}

		fmt.Println("Validated!")
	}
}
