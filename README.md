# Yubikey
This library allows you to validate Yubikey OTPs against the Yubico API.

## Usage

### Checking if a string is an OTP
```go
client := yubikey.New("#####", nil)
otp := "some yubikey otp"

// Make sure the OTP is valid.
if err := client.IsValidOTP(otp); err != nil {
    fmt.Printf("Invalid OTP: %s\n", err.Error())
    return
}

fmt.Println("Valid OTP")
```

### Validating a OTP
```go
client := yubikey.New("#####", nil)
otp := "some yubikey otp"

// Make sure to use Client#IsValidOTP before validating
// the OTP using Client#Validate

// Validate the OTP.
if err := client.Validate(otp); err != nil {
    fmt.Printf("Validation Error: %s\n", err.Error())
    return
}

fmt.Println("Validated")
```

### Linking a Yubikey to a User
```go
client := yubikey.New("#####", nil)
otp := "some yubikey otp"

// Make sure to use Client#IsValidOTP before using Client#GetIdentity

identity := client.GetIdentity()
if identity == "" {
    fmt.Println("Invalid OTP")
    return
}

fmt.Printf("Identity: %s\n", identity)

// Then you can use the identity string to match the beginning of a OTP to verify the OTP
// came from the user once it is validated by Client#Validate
```

For an interactive example checkout [example/main.go](https://github.com/matthewpi/yubikey/blob/develop/example/main.go).


