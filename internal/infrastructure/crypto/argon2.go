package crypto

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Hasher implements password hashing using Argon2id.
// Argon2id is the recommended algorithm for password hashing (OWASP).
type Argon2Hasher struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

// NewArgon2Hasher creates a new Argon2id hasher with the given parameters.
func NewArgon2Hasher(memory, iterations uint32, parallelism uint8, saltLength, keyLength uint32) *Argon2Hasher {
	return &Argon2Hasher{
		memory:      memory,
		iterations:  iterations,
		parallelism: parallelism,
		saltLength:  saltLength,
		keyLength:   keyLength,
	}
}

// Hash generates an Argon2id hash of the password.
// Returns a string in the format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func (h *Argon2Hasher) Hash(password string) (string, error) {
	salt := make([]byte, h.saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	hash := argon2.IDKey(
		[]byte(password),
		salt,
		h.iterations,
		h.memory,
		h.parallelism,
		h.keyLength,
	)

	// Encode to PHC string format
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.memory,
		h.iterations,
		h.parallelism,
		b64Salt,
		b64Hash,
	)

	return encoded, nil
}

// Verify checks if a password matches an Argon2id hash.
// Uses constant-time comparison to prevent timing attacks.
func (h *Argon2Hasher) Verify(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	params, salt, hash, err := h.decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	// Compute the hash of the provided password using the same parameters
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		params.iterations,
		params.memory,
		params.parallelism,
		params.keyLength,
	)

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(hash, computedHash) == 1 {
		return true, nil
	}

	return false, nil
}

// NeedsRehash checks if the hash was created with different parameters.
// Used to upgrade hashes when security parameters change.
func (h *Argon2Hasher) NeedsRehash(encodedHash string) (bool, error) {
	params, _, _, err := h.decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	return params.memory != h.memory ||
		params.iterations != h.iterations ||
		params.parallelism != h.parallelism ||
		params.keyLength != h.keyLength, nil
}

// argon2Params holds the parameters extracted from an encoded hash.
type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32
}

// decodeHash parses an encoded Argon2id hash string.
func (h *Argon2Hasher) decodeHash(encodedHash string) (*argon2Params, []byte, []byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, nil, nil, fmt.Errorf("invalid hash format")
	}

	if parts[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("unsupported algorithm: %s", parts[1])
	}

	var version int
	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid version: %w", err)
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("incompatible argon2 version")
	}

	params := &argon2Params{}
	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid salt: %w", err)
	}

	hash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid hash: %w", err)
	}

	params.keyLength = uint32(len(hash))

	return params, salt, hash, nil
}
