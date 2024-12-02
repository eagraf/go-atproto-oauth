# AT Protocol OAuth2 Go Example

This is a example project showing how to implement an Golang web service which uses atproto OAuth for authentication.

[python-oauth-web-app](https://github.com/bluesky-social/cookbook/tree/main/python-oauth-web-app) is used as a reference for the implementation.

## Prerequisites

- Go 1.22 or later
- A domain with HTTPS support (for production use)
- A Bluesky(or AT Protocol) account

## Setup

1. Clone the repository:
```bash
git clone https://github.com/potproject/atproto-oauth2-go-example.git
cd atproto-oauth2-go-example
```

2. Install dependencies:
```bash
go mod download
```

3. Generate a Secret JWK:
```bash
go run genKey/main.go
```

4. Create a `.env` file based on `.env.example`:
```bash
HOST=your-domain.com    # Your domain
PORT=3000              # Port to run the server on
SECRET_JWK='...'       # The Secret JWK generated in step 3
```

## Running the Server

Start the server:
```bash
go run main.go
# However, you need a site that is actually published with https
```

The server will start on the specified port with the following endpoints:

- `/`: Login page
- `/login`: Handle login requests
- `/callback`: OAuth callback endpoint
- `/jwks.json`: JWKS endpoint
- `/client_metadata.json`: Client metadata endpoint

## Flow

1. User enters their Bluesky handle on the login page
2. Server resolves the handle to a DID
3. Server resolves the DID to a PDS (Personal Data Server)
4. Server performs PAR with the PDS
5. User is redirected to the Bluesky authorization page
6. After authorization, user is redirected back to the callback endpoint

## License

MIT
