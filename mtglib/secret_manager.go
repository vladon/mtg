package mtglib

import (
	"errors"
	"sync"

	"github.com/9seconds/mtg/v2/mtglib/internal/faketls"
)

var (
	// ErrNoMatchingSecret is returned when no secret matches the client hello
	ErrNoMatchingSecret = errors.New("no matching secret found")
)

// SecretManager manages multiple secrets and provides efficient secret matching
type SecretManager struct {
	secrets    []Secret
	secretMap  map[string]*Secret // key: first 8 bytes for quick matching
	mutex      sync.RWMutex
}

// NewSecretManager creates a new secret manager with the given secrets
func NewSecretManager(secrets []Secret) *SecretManager {
	if len(secrets) == 0 {
		return nil
	}

	sm := &SecretManager{
		secrets:   make([]Secret, len(secrets)),
		secretMap: make(map[string]*Secret),
	}

	copy(sm.secrets, secrets)

	// Build prefix map for faster lookup
	for i := range secrets {
		if len(secrets[i].Key) >= 8 {
			prefix := string(secrets[i].Key[:8])
			sm.secretMap[prefix] = &sm.secrets[i]
		}
	}

	return sm
}

// FindSecret attempts to find a matching secret for the given client hello data
func (sm *SecretManager) FindSecret(clientHello []byte) (*Secret, error) {
	if sm == nil {
		return nil, ErrNoMatchingSecret
	}

	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	// First try prefix-based lookup for efficiency
	if len(clientHello) >= 8 {
		prefix := string(clientHello[:8])
		if secret, exists := sm.secretMap[prefix]; exists {
			// Validate this secret actually works with the client hello
			if _, err := faketls.ParseClientHello(secret.Key[:], clientHello); err == nil {
				return secret, nil
			}
		}
	}

	// Fallback to linear search if prefix lookup fails
	for i := range sm.secrets {
		if _, err := faketls.ParseClientHello(sm.secrets[i].Key[:], clientHello); err == nil {
			return &sm.secrets[i], nil
		}
	}

	return nil, ErrNoMatchingSecret
}

// GetSecrets returns a copy of all managed secrets
func (sm *SecretManager) GetSecrets() []Secret {
	if sm == nil {
		return nil
	}

	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	result := make([]Secret, len(sm.secrets))
	copy(result, sm.secrets)
	return result
}

// Count returns the number of managed secrets
func (sm *SecretManager) Count() int {
	if sm == nil {
		return 0
	}

	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return len(sm.secrets)
}

// GetDefaultSecret returns the first secret (for backward compatibility)
func (sm *SecretManager) GetDefaultSecret() *Secret {
	if sm == nil || len(sm.secrets) == 0 {
		return nil
	}

	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	return &sm.secrets[0]
}