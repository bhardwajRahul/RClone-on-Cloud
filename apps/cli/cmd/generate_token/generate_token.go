package generate_token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func GenerateToken(private_key_file_path string, user_id string, email string) (*string, error) {
	privateKey, err := loadRSAPrivateKey(private_key_file_path)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	claims := jwt.MapClaims{
		"sub":   user_id,
		"email": email,
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(24 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign token: %w", err)
	}

	return &signed, nil
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	if path == "" {
		return nil, fmt.Errorf("JWT_PRIVATE_KEY_PATH is not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("private key file is not valid PEM")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}
	return rsaPriv, nil
}
