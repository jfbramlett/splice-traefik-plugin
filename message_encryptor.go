package splicetraefikplugin

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"log"
	"strings"
)

type MessageEncryptor struct {
	Key []byte
	// optional property used to automatically set the
	// verifier if not already set.
	SignKey  []byte
	Cipher   string
	Verifier *MessageVerifier
}

func (crypt *MessageEncryptor) DecryptAndVerify(msg string, target *Session) error {

	crypt.Verifier = &MessageVerifier{
		Secret: crypt.SignKey,
		Hasher: sha1.New,
	}

	log.Default().Printf("verifying cookie value %s", msg)

	base64Msg, err := crypt.Verifier.Verify(msg)
	if err != nil {
		return errors.New("Verification failed: " + err.Error())
	}
	return crypt.Decrypt(base64Msg, target)
}

// Decrypt decrypts a message using the set cipher and the secret.
// The passed value is expected to be a base 64 encoded string of the encrypted data + IV joined by "--"
func (crypt *MessageEncryptor) Decrypt(value string, target *Session) error {
	return crypt.aesCbcDecrypt(value, target)
}

func (crypt *MessageEncryptor) aesCbcDecrypt(encryptedMsg string, target *Session) error {
	log.Default().Printf("descrypting cookie value %s", encryptedMsg)

	k := crypt.Key
	// The longest accepted key is 32 byte long,
	// instead of rejecting a long key, we truncate it.
	// This is how openssl in Ruby works.
	if len(k) > 32 {
		k = crypt.Key[:32]
	}

	block, err := aes.NewCipher(k)
	if err != nil {
		return err
	}

	// split the msg and decode each part
	splitMsg := strings.Split(encryptedMsg, "--")
	if len(splitMsg) != 2 {
		return errors.New("bad data (--)")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(splitMsg[0])
	if err != nil {
		return err
	}
	iv, err := base64.StdEncoding.DecodeString(splitMsg[1])
	if err != nil {
		return err
	}

	if len(ciphertext) < aes.BlockSize {
		return errors.New("bad data, ciphertext too short")
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return errors.New("bad data, ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	unPaddedCiphertext := PKCS7Unpad(ciphertext)

	unPaddedCiphertext = bytes.TrimRight(unPaddedCiphertext, "\x10")

	return Unserialize(unPaddedCiphertext, target)
}

// PKCS7Unpad removes any potential PKCS7 padding added.
func PKCS7Unpad(data []byte) []byte {
	dataLen := len(data)
	// Edge case
	if dataLen == 0 {
		return nil
	}
	// the last byte indicates the length of the padding to remove
	paddingLen := int(data[dataLen-1])

	// padding length can only be between 1-15
	if paddingLen < 16 {
		return data[:dataLen-paddingLen]
	}
	return data
}

func Key(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha1.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}

// MessageVerifier makes it easy to generate and verify messages which are
// signed to prevent tampering.
//
// This is useful for cases like remember-me tokens and auto-unsubscribe links
// where the session store isn't suitable or available.
type MessageVerifier struct {
	// Secret of 32-bytes if using the default hashing.
	Secret []byte
	// Hasher defaults to sha1 if not set.
	Hasher func() hash.Hash
}

func (crypt *MessageVerifier) Verify(msg string) (string, error) {
	err := crypt.checkInit()
	if err != nil {
		return "", err
	}

	invalid := func(msg string) error {
		return errors.New("Invalid signature - " + msg)
	}
	if msg == "" {
		return "", invalid("empty message")
	}

	dataDigest := strings.Split(msg, "--")
	if len(dataDigest) != 2 {
		return "", invalid("bad data --")
	}

	data, digest := dataDigest[0], dataDigest[1]
	if !crypt.secureCompare(digest, crypt.DigestFor(data)) {
		return "", invalid("bad data (compare)")
	}
	decodedString, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}
	return string(decodedString), nil
}

// DigestFor returns the digest form of a string after hashing it via
// the verifier's digest and secret.
func (crypt *MessageVerifier) DigestFor(data string) string {
	if crypt.Secret == nil {
		return "Y U SET NO SECRET???!"
	}

	mac := hmac.New(crypt.Hasher, crypt.Secret)
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}

// constant-time comparison algorithm to prevent timing attacks
func (crypt *MessageVerifier) secureCompare(strA, strB string) bool {
	a := []byte(strA)
	b := []byte(strB)

	if len(a) != len(b) {
		return false
	}
	res := 0
	for i := 0; i < len(a); i++ {
		res |= int(b[i]) ^ int(a[i])
	}
	return res == 0
}

func (crypt *MessageVerifier) checkInit() error {
	if crypt == nil {
		return errors.New("MessageVerifier not set")
	}

	if crypt.Hasher == nil {
		// set a default hasher
		crypt.Hasher = sha1.New
	}

	if crypt.Secret == nil {
		return errors.New("Secret not set")
	}

	return nil
}

func Unserialize(data []byte, session *Session) error {
	log.Default().Printf("unserializing cookie value %s", string(data))

	return json.Unmarshal(data, session)
}
