package gosalty

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
)

func To32BytesHash(slices ...[]byte) []byte {
	hashed := sha256.Sum256(bytes.Join(slices, []byte{}))
	return hashed[:]
}

func Encode(plain, password []byte) ([]byte, error) {
	paddingLength := aes.BlockSize - (len(plain) % aes.BlockSize)
	plain = append(plain, bytes.Repeat([]byte{byte(paddingLength)}, paddingLength)...)

	iv := make([]byte, aes.BlockSize)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, err
	}

	ci, err := aes.NewCipher(To32BytesHash(password))
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(ci, iv)

	encoded := make([]byte, len(plain))
	for index := range len(plain) / aes.BlockSize {
		i1 := index * aes.BlockSize
		i2 := (index + 1) * aes.BlockSize
		mode.CryptBlocks(encoded[i1:i2], plain[i1:i2])
	}

	return append(iv, encoded...), nil
}

func Decode(encoded, password []byte) ([]byte, error) {
	iv := encoded[:aes.BlockSize]
	encoded = encoded[aes.BlockSize:]

	ci, err := aes.NewCipher(To32BytesHash(password))
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(ci, iv)

	plain := make([]byte, len(encoded))
	for index := range len(encoded) / aes.BlockSize {
		i1 := index * aes.BlockSize
		i2 := (index + 1) * aes.BlockSize
		mode.CryptBlocks(plain[i1:i2], encoded[i1:i2])
	}

	paddingSize := plain[len(plain)-1]

	return plain[:len(plain)-int(paddingSize)], nil
}

func SaltyEncode(plain, password, salt []byte) ([]byte, error) {
	return Encode(plain, append(password, salt...))
}

func SaltyDecode(content, password, salt []byte) ([]byte, error) {
	return Decode(content, append(password, salt...))
}

func SaltyEncodeToHexString(plain, password, salt []byte) (string, error) {
	encoded, err := SaltyEncode(plain, password, salt)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encoded), nil
}

func SaltyDecodeFromHexString(encoded string, password, salt []byte) ([]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return SaltyDecode(decoded, password, salt)
}

func SaltyEncodeToBase64(plain, password, salt []byte) (string, error) {
	encoded, err := SaltyEncode(plain, password, salt)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encoded), nil
}

func SaltyDecodeFromBase64(encoded string, password, salt []byte) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return SaltyDecode(decoded, password, salt)
}
