package generate_token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ekarton/RClone-Cloud/apps/cli/cmd/generate_token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateToken(t *testing.T) {
	// 1. Generate a temporary RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)

	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "private_key.pem")

	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	})
	require.NoError(t, err)
	keyFile.Close()

	// 2. Test successful token generation
	userID := "user-123"
	email := "user@example.com"
	tokenPtr, err := generate_token.GenerateToken(keyPath, userID, email)
	require.NoError(t, err)
	require.NotNil(t, tokenPtr)

	tokenStr := *tokenPtr

	// 3. Verify the token
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, assert.AnError
		}
		return &privateKey.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)
	assert.Equal(t, userID, claims["sub"])
	assert.Equal(t, email, claims["email"])

	// Verify expiration is set (roughly 24 hours from now)
	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	assert.Greater(t, int64(exp), int64(0))

	// 4. Test error cases
	t.Run("Missing File", func(t *testing.T) {
		_, err := generate_token.GenerateToken("non_existent_path", userID, email)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "read private key")
	})

	t.Run("Invalid PEM", func(t *testing.T) {
		badFilePath := filepath.Join(tempDir, "bad_key.pem")
		err := os.WriteFile(badFilePath, []byte("NOT A PEM"), 0644)
		require.NoError(t, err)

		_, err = generate_token.GenerateToken(badFilePath, userID, email)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not valid PEM")
	})
}
