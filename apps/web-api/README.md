# RClone-Cloud Web API

This is a web API for RClone-Cloud.

## Features

- [x] OAuth2 authentication
- [x] Full RClone RCD support (https://rclone.org/commands/rclone_rcd)

## Getting started

Prerequisites:

- Docker
- Go

Install dependencies by running:

```shell
go install .
```

Run the app locally by running:

```shell
go run .
```

Build the app by running:

```shell
mkdir -p bin
go build -o bin/rclone-svc .
```

Run tests by running:

```shell
go test ./... -coverprofile=coverage.out
```

See code coverage after running the above command:

```shell
go tool cover -html=coverage.out
```
