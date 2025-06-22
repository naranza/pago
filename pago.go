// Naranza Pago, Copyright 2025 Andrea Davanzo and contributors, GPLv3

package pago

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const Version = "0.2025.1"

const (
	saltLength  = 16
	keyLength   = 32
	version     = argon2.Version
)

type Params struct {
	Memory uint32
	TimeCost uint32
	Parallelism uint8
}

func DefaultParams() Params {
	return Params{
	  Memory: 64 * 1024, // 64 MB
	  TimeCost: 4,
	  Parallelism: 1,
  }
}

// GenerateSalt returns a securely generated random salt of the given length.
func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
	_, err := rand.Read(salt);
	if err != nil {
		salt = nil
	}
	return salt, err
}

func Hash(password string, p *Params) (string, error) {

	var params Params
  if p == nil {
    params = DefaultParams()
  } else {
    params = *p
  }

	encoded := ""
	salt, err := GenerateSalt(saltLength)
	if err == nil {
		hash := argon2.IDKey(
			[]byte(password),
			salt,
			params.TimeCost,
			params.Memory,
			params.Parallelism,
			keyLength)

		b64Salt := base64.RawStdEncoding.EncodeToString(salt)
		b64Hash := base64.RawStdEncoding.EncodeToString(hash)

		encoded = fmt.Sprintf(
			"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
			argon2.Version,
			params.Memory,
			params.TimeCost,
			params.Parallelism,
			b64Salt,
			b64Hash)
	}
	return encoded, err
}

func Verify(password, encodedHash string) (bool, error) {

	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, errors.New("Invalid number of parts")
	}
	
	if parts[1] != "argon2id" {
		return false, errors.New("Invalid prefix")
	}

	var version int
	var memory uint32
	var timeCost uint32
	var parallelism uint8
	var err error
	var salt []byte
	var expectedHash []byte

	_, err = fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return false, errors.New("Incompatible version")
	}

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &parallelism)
	if err != nil {
		return false, errors.New("Invalid params")
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errors.New("Salt decode error")
	}

	expectedHash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errors.New("Hash decode error")
	}

	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		timeCost,
		memory,
		parallelism,
		uint32(len(expectedHash)),
	)

	return subtle.ConstantTimeCompare(expectedHash, computedHash) == 1, nil
}


