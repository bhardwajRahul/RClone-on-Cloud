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
	"github.com/stretchr/testify/require"
)

func TestGenerateTokenCobraCmd(t *testing.T) {
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

	// 2. Execute Command via Cobra
	// Note: We need to capture stdout to verify the token, but for now we just check it runs without error.
	cmd := generate_token.GenerateTokenCmd
	cmd.SetArgs([]string{keyPath, "user-123", "user@example.com"})

	// We use a fake output buffer to avoid cluttering test output
	// Alternatively, we could verify the printed token by parsing it.
	err = cmd.Execute()
	require.NoError(t, err)
}
