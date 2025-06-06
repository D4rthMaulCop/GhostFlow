# Overview

GhostFlow is a device code phishing framework designed to steak Entra ID user tokens using Microsoft's device code authentication flow. Upon successful authentication, users are redirected to download a static decoy document (e.g., pwnded.pdf) and save the access and refresh tokens to a JSON file. These tokens can be used to authenticate to other Microsoft APIs/services. GhostFlow uses the Microsoft Office client ID and currently uses a Microsoft-themed login page but can be easily extended or replaced.

![alt text](https://github.com/D4rthMaulCop/GhostFlow/blob/main/img/poc.png)

![alt text](https://github.com/D4rthMaulCop/GhostFlow/blob/main/img/poc2.png)

## Features
- Uses Go HTML template engine for easy phishing page development
- Cookie-based UUID tracking for users using the `auth_uuid` cookie to uniquelly track tokens
- Configurable decoy PDF served upon successful login to "close the loop" with the target
- Fully HTTPS-capable self-signed certificates or custom certificates via LetsEncrypt
- Tokens are saved to `tokens/tokens_<uuid>.json`
- Console logs track token capture
- Landing page refreshes every 13 minutes to ensure device code is valid (in case a user clicks on a link but doesn't immediately go through with the authentication)
- Common bot user agent blocking

## Authentication Flow
1. Visitor lands on `/`
2. Framework requests a Microsoft device code
3. User is shown:
   - Device login code
   - Microsoft login link (`https://microsoft.com/devicelogin`)
4. Upon successful login:
   - Access/refresh token is saved to `tokens/`
   - User is redirected to `/download`
   - `pwned.pdf` is served if token is found

## Project Structure
```
project/
├── main.go
├── templates/
│   ├── index.html
│   └── unauthorized.html
├── pwned.pdf
├── cert.pem
├── key.pem
├── makefile
```

## Usage
```
-debug
   Run locally in debug mode using cert.pem and key.pem
-decoy string
   File to serve after successful authentication
-domain string
   The domain to use for TLS (must point to this server)
```

## Example
```
sudo ./GhostFlow -domain superbadserver.com --decoy=pwned.pdf
```

# Deployment 
### Build the project
```bash
make
```
### Generate Self-Signed TLS Certs (if testing)
```bash
openssl req -x509 -newkey rsa:4096 -sha256 -nodes -keyout key.pem -out cert.pem -days 365
```
### Run the Server

```bash
sudo ./GhostFlow -decoy=pwned.pdf -debug
```
OR 
```bash
sudo ./GhostFlow -domain superbadserver.com -decoy pwned.pdf
```
