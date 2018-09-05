# Chatterbox

## Overview

This is a simple golang client to send messages to
[chatterbox](https://github.com/github/chatterbox), GitHub's simple API to send
messages into chat.

## Example


```go
package main

import (
	"github.com/github/go/chatterbox"
	"log"
	"os"
)

func main() {
	token := os.Getenv("CHATTERBOX_TOKEN")
	url := os.Getenv("CHATTERBOX_URL")

	// use the one-line version for single messages
	err := chatterbox.Say(token, url, "dumping-ground", "Hello, world!")
	if err != nil {
		log.Fatalf("Error sending to chatterbox: %v", err)
	}

	// use the chatterbox.Client version when you might be sending multiple
	// messages around
	client, err := chatterbox.New(token, url)
	if err != nil {
		log.Fatalf("Error connecting to chatterbox: %v", err)
	}
	err = client.Say("dumping-ground", "Hello, world again!")
	if err != nil {
		log.Fatalf("Error sending to chatterbox: %v", err)
	}

}

```

Check out `godoc -ex chatterbox` for more documentation
