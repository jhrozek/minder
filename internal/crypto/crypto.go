//
// Copyright 2023 Stacklok, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package crypto provides cryptographic functions
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	serverconfig "github.com/stacklok/minder/internal/config/server"
)

// TODO: The crypto-level engine should not export high level functions like EncryptOAuthToken and DecryptOAuthToken but
// instead should only provide low level functions like EncryptBytes and DecryptBytes. The high level functions should be
// wrapping the low level engine

// Engine provides all functions to encrypt and decrypt data
type Engine interface {
	EncryptOAuthToken(data []byte) (string, []byte, error)
	DecryptOAuthToken(salt []byte, encToken string) (oauth2.Token, error)
	EncryptString(data string) (string, []byte, error)
	DecryptString(salt []byte, encData string) (string, error)
}

// AesCfbEngine is a structure that allows controller access to cryptographic functions.
// The intention is that this structure will be passed to the controller on creation
// and will validate that wrong parameters aren't passed to the functions.
type AesCfbEngine struct {
	encryptionKey string
}

// EngineFromAuthConfig creates a new crypto engine from an auth config
func EngineFromAuthConfig(authConfig *serverconfig.AuthConfig) (Engine, error) {
	if authConfig == nil {
		return nil, errors.New("auth config is nil")
	}

	keyBytes, err := authConfig.GetTokenKey()
	if err != nil {
		return nil, fmt.Errorf("failed to read token key file: %s", err)
	}

	return NewEngine(string(keyBytes)), nil
}

// NewEngine creates a new crypto engine
func NewEngine(tokenKey string) Engine {
	return &AesCfbEngine{
		encryptionKey: tokenKey,
	}
}

// EncryptBytes encrypts a row of data using AES-CFB.
func EncryptBytes(
	key string, data []byte,
) (encrypted []byte, salt []byte, err error) {
	salt = make([]byte, 16)
	_, err = rand.Read(salt)
	if err != nil {
		return
	}

	if len(data) > 1024*1024*32 {
		err = status.Errorf(codes.InvalidArgument, "data is too large (>32MB)")
		return
	}
	block, err := aes.NewCipher(deriveKey(key, salt))
	if err != nil {
		err = status.Errorf(codes.Unknown, "failed to create cipher: %s", err)
		return
	}

	// The IV needs to be unique, but not secure. Therefore it's common to include it at the beginning of the ciphertext.
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, readErr := io.ReadFull(rand.Reader, iv); readErr != nil {
		err = status.Errorf(codes.Unknown, "failed to read random bytes: %s", readErr)
		return
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(data))

	encrypted = ciphertext
	return
}

// EncryptOAuthToken encrypts an oauth token
func (e *AesCfbEngine) EncryptOAuthToken(data []byte) (string, []byte, error) {
	encryptedToken, salt, err := EncryptBytes(e.encryptionKey, data)
	if err != nil {
		return "", nil, err
	}
	encodedToken := base64.StdEncoding.EncodeToString(encryptedToken)
	return encodedToken, salt, nil
}

// DecryptOAuthToken decrypts an encrypted oauth token
func (e *AesCfbEngine) DecryptOAuthToken(salt []byte, encToken string) (oauth2.Token, error) {
	var decryptedToken oauth2.Token

	// base64 decode the token
	decodeToken, err := base64.StdEncoding.DecodeString(encToken)
	if err != nil {
		return decryptedToken, err
	}

	// decrypt the token
	token, err := decryptBytes(e.encryptionKey, salt, decodeToken)
	if err != nil {
		return decryptedToken, err
	}

	// serialise token *oauth.Token
	err = json.Unmarshal(token, &decryptedToken)
	if err != nil {
		return decryptedToken, err
	}
	return decryptedToken, nil
}

// EncryptString encrypts a string
func (e *AesCfbEngine) EncryptString(data string) (string, []byte, error) {
	var encoded string

	encrypted, salt, err := EncryptBytes(e.encryptionKey, []byte(data))
	if err != nil {
		return encoded, nil, err
	}

	encoded = base64.StdEncoding.EncodeToString(encrypted)

	return encoded, salt, nil
}

// DecryptString decrypts an encrypted string
func (e *AesCfbEngine) DecryptString(salt []byte, encData string) (string, error) {
	var decrypted string

	// base64 decode the string
	decodeToken, err := base64.StdEncoding.DecodeString(encData)
	if err != nil {
		return decrypted, err
	}

	// decrypt the string
	token, err := decryptBytes(e.encryptionKey, salt, decodeToken)
	if err != nil {
		return decrypted, err
	}

	return string(token), nil
}

// decryptBytes decrypts a row of data
func decryptBytes(key string, salt, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(deriveKey(key, salt))
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "failed to create cipher: %s", err)
	}

	// The IV needs to be extracted from the ciphertext.
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}

// Function to derive a key from a passphrase using Argon2
func deriveKey(passphrase string, salt []byte) []byte {
	// In a real application, you should use a unique salt for
	// each key and save it with the encrypted data.
	if len(salt) == 0 {
		salt = []byte("somesalt")
	}
	return argon2.IDKey([]byte(passphrase), salt, 1, 64*1024, 4, 32)
}

// GenerateNonce generates a nonce for the OAuth2 flow. The nonce is a base64 encoded
func GenerateNonce() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	nonceBytes := make([]byte, 8)
	timestamp := time.Now().Unix()
	binary.BigEndian.PutUint64(nonceBytes, uint64(timestamp))

	nonceBytes = append(nonceBytes, randomBytes...)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	return nonce, nil
}

// IsNonceValid checks if a nonce is valid. A nonce is valid if it is a base64 encoded string
func IsNonceValid(nonce string, noncePeriod int64) (bool, error) {
	nonceBytes, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return false, err
	}

	if len(nonceBytes) < 8 {
		return false, nil
	}

	storedTimestamp := int64(binary.BigEndian.Uint64(nonceBytes[:8]))
	currentTimestamp := time.Now().Unix()
	timeDiff := currentTimestamp - storedTimestamp

	if timeDiff > noncePeriod { // 5 minutes = 300 seconds
		return false, nil
	}

	return true, nil
}
