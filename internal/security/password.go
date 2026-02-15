package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	passwordHashVersion = "v1"
	iterations          = 180000
)

func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	digest := deriveDigest(password, salt, iterations)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedDigest := base64.RawStdEncoding.EncodeToString(digest)

	return fmt.Sprintf("%s$%d$%s$%s", passwordHashVersion, iterations, encodedSalt, encodedDigest), nil
}

func VerifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 {
		return false
	}
	if parts[0] != passwordHashVersion {
		return false
	}

	iters, err := strconv.Atoi(parts[1])
	if err != nil || iters < 100000 {
		return false
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil || len(salt) == 0 {
		return false
	}

	expectedDigest, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(expectedDigest) != sha256.Size {
		return false
	}

	actualDigest := deriveDigest(password, salt, iters)
	return subtle.ConstantTimeCompare(actualDigest, expectedDigest) == 1
}

func deriveDigest(password string, salt []byte, rounds int) []byte {
	digest := sha256.Sum256(append(salt, []byte(password)...))
	buf := digest[:]
	for i := 1; i < rounds; i++ {
		next := sha256.Sum256(append(buf, salt...))
		buf = next[:]
	}
	finalDigest := make([]byte, len(buf))
	copy(finalDigest, buf)
	return finalDigest
}
