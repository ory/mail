# ory/mail

This is a fork of the abandoned [go-mail/mail](https://github.com/go-mail/mail) which is an
abandoned fork of [go-gomail/gomail](https://github.com/go-gomail/gomail) 

## Introduction

ory/mail is a simple and efficient package to send emails. It is well tested and
documented.

ory/mail can only send emails using an SMTP server. But the API is flexible and it
is easy to implement other methods for sending emails using a local Postfix, an
API, etc.

## Features

ory/mail supports:
- Attachments
- Embedded images
- HTML and text templates
- Automatic encoding of special characters
- SSL and TLS
- Sending multiple emails with the same SMTP connection

## Documentation

https://godoc.org/github.com/go-mail/mail

## Use

```shell script
$ go get github.com/ory/mail/v3
```

## FAQ

### x509: certificate signed by unknown authority

If you get this error it means the certificate used by the SMTP server is not
considered valid by the client running ory/mail. As a quick workaround you can
bypass the verification of the server's certificate chain and host name by using
`SetTLSConfig`:

```go
package main

import (
	"crypto/tls"

	"github.com/ory/mail"
)

func main() {
	d := mail.NewDialer("smtp.example.com", 587, "user", "123456")
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	// Send emails using d.
}
```

Note, however, that this is insecure and should not be used in production.

## Contribute

Contributions are more than welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for
more info.
