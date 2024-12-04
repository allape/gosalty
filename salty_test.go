package gosalty

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

var (
	TextSalt = []byte("text")
)

var (
	Password     = []byte("password")
	HashPassword = To32BytesHash(Password, TextSalt)
)

func TestEncode(t *testing.T) {
	secret := []byte("my little tiny teeny secret")

	t.Log(string(secret))
	t.Log(hex.EncodeToString(HashPassword))

	encoded, err := SaltyEncodeToHexString(secret, Password, TextSalt)
	if err != nil {
		t.Fatalf("SaltyEncodeToHexString failed: %v", err)
	}

	t.Logf("encoded: %s", encoded)

	if encoded == hex.EncodeToString(secret) {
		t.Fatalf("SaltyEncodeToHexString failed: encoded == secret")
	}

	decoded, err := SaltyDecodeFromHexString(encoded, Password, TextSalt)
	if err != nil {
		t.Fatalf("SaltyDecodeFromHexString failed: %v", err)
	}

	t.Logf("decoded: %s", decoded)

	if bytes.Compare(secret, decoded) != 0 {
		t.Fatalf("SaltyDecodeFromHexString failed: secret != decoded")
	}

	encoded, err = SaltyEncodeToBase64(secret, Password, TextSalt)
	if err != nil {
		t.Fatalf("SaltyEncodeToBase64 failed: %v", err)
	}

	t.Logf("encoded: %s", encoded)

	if encoded == base64.StdEncoding.EncodeToString(secret) {
		t.Fatalf("SaltyEncodeToBase64 failed: encoded == secret")
	}

	decoded, err = SaltyDecodeFromBase64(encoded, Password, TextSalt)
	if err != nil {
		t.Fatalf("SaltyDecodeFromBase64 failed: %v", err)
	}

	t.Logf("decoded: %s", decoded)

	if bytes.Compare(secret, decoded) != 0 {
		t.Fatalf("SaltyDecodeFromBase64 failed: secret != decoded")
	}
}
