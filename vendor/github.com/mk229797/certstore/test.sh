#!/bin/bash
go get -t -d -v ./...
go clean
go build
go test
