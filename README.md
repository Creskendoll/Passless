# Passless

Passless is an experimental demonstration of an encrypted file storage web application which uses a six-word passphrase for authenticaton and key derivation. At the moment, it only works with very small files. Absolutely no guarantees are made about availability of this application or any data which you might store on it!

## Run the development environment

```
git clone https://github.com/RyanHopkins7/Passless.git
docker run -p 27017:27017 --name mongodb -d mongo:latest
cd Passless
npm install
npm run dev
```

You should then be able to view the project at http://localhost:3000

## Deploy / redeploy the production server

```
cd Passless
git pull
sudo ./deploy.sh
```

## How it works

### Account registration

When a user registers an account for the first time,

1. The user's username and six word passphrase are randomly selected for them using a cryptographically secure PRNG
2. A "vault key" is randomly generated on the user's device which will be used to encrypt and decrypt files
3. The passphrase is hashed using PBKDF2 with the username as salt in order to derive the authentication key
4. The passphrase is also used to generate a wrapping key with PBKDF2 using a random salt
5. The passphrase-derived wrapping key is used to wrap the "vault key"
6. The authentication key is sent to the server, re-hashed using Argon2id, and saved
7. The wrapped "vault key" is also sent to the server and saved

### Signing in

When a user signs into their account,

1. The user enters their username and passphrase
2. The username and passphrase are used to derive the authentication key
3. The authentication key is validated by the server
4. If the authentication is successful, then the server will send the wrapped "vault key" to the user
5. The passphrase will then be used to regenerate the wrapping key
6. The wrapping key will then be used to unwrap the "vault key"
7. The user's device will then randomly generate a "device key" and save it to the local storage of their browser
8. The user's "device key" will then be used to wrap the "vault key"
9. The newly wrapped "vault key" will then be sent back to the server and saved

### The vault

When an authenticated user visits the vault page,

1. The server will send the user their wrapped "vault key" which was wrapped with the "device key"
2. The user will use their saved "device key" to unwrap the "vault key"
3. The "vault key" can then be used to encrypt and decrypt files when sending and receiving file data to the server
