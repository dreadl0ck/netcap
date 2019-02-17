/*
 * CRYPTOUTILS - A thin wrapper for the x/crypto/nacl package and a few utils
 * Copyright (c) 2017 Philipp Mieden <dreadl0ck [at] protonmail [dot] ch>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package cryptoutils

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	// ErrEncrypt means something went wrong encrypting
	// ErrEncrypt = errors.New("error encrypting")

	// ErrDecrypt means something went wrong decrypting
	ErrDecrypt = errors.New("error decrypting")

	// ErrEmptyFile means the file is empty
	ErrEmptyFile = errors.New("file is empty")
)

// KeySize is 256bit
const (
	KeySize   = 32
	NonceSize = 24
)

// HashFunc is a function that calculates a hash
type HashFunc func([]byte) []byte

/*
 *	Nonce
 */

// GenerateNonce creates a new random nonce.
func GenerateNonce() (*[NonceSize]byte, error) {

	// alloc
	nonce := new([NonceSize]byte)

	// read from rand.Reader
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

/*
 *	Symmetric Encryption / Decryption
 */

// SymmetricEncryptStatic encrypts using a fixed nonce
func SymmetricEncryptStatic(data string, staticNonce *[NonceSize]byte, key *[KeySize]byte) []byte {

	// use the key as nonce
	out := make([]byte, NonceSize)

	copy(out, staticNonce[:])

	// encrypt with secretbox
	return secretbox.Seal(out, []byte(data), staticNonce, key)
}

// SymmetricEncrypt generates a random nonce and encrypts the input using
// NaCl's secretbox package. The nonce is prepended to the ciphertext.
// A sealed message will the same size as the original message + secretbox.Overhead bytes long.
func SymmetricEncrypt(data []byte, key *[KeySize]byte) ([]byte, error) {

	// generate a new nonce
	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	out := make([]byte, NonceSize)
	copy(out, nonce[:])

	// encrypt with secretbox
	out = secretbox.Seal(out, data, nonce, key)
	return out, nil
}

// SymmetricDecrypt extracts the nonce from the ciphertext, and attempts to decrypt with NaCl's secretbox.
func SymmetricDecrypt(data []byte, key *[KeySize]byte) ([]byte, error) {

	// check if data is valid
	if len(data) < (NonceSize + secretbox.Overhead) {
		return nil, ErrDecrypt
	}

	// extract nonce
	var nonce [NonceSize]byte
	copy(nonce[:], data[:NonceSize])

	// decrypt with secretbox
	out, ok := secretbox.Open(nil, data[NonceSize:], &nonce, key)
	if !ok {
		return nil, ErrDecrypt
	}

	return out, nil
}

/*
 *	Asymmetric Encryption / Decryption
 */

// AsymmetricEncrypt encrypts a message for the given pubKey
func AsymmetricEncrypt(data []byte, pubKey, privKey *[KeySize]byte) ([]byte, error) {

	nonce, err := GenerateNonce()
	if err != nil {
		return nil, err
	}

	// fmt.Println("nonce: ", hex.EncodeToString(nonce[:]))

	// init out and append nonce
	out := make([]byte, NonceSize)
	copy(out, nonce[:])

	return box.Seal(out, data, nonce, pubKey, privKey), nil
}

// AsymmetricDecrypt decrypts a message
func AsymmetricDecrypt(data []byte, pubKey, privKey *[KeySize]byte) ([]byte, bool) {

	// extract nonce
	var nonce [NonceSize]byte
	copy(nonce[:], data[:NonceSize])

	// fmt.Println("extracted nonce: ", hex.EncodeToString(nonce[:]))

	return box.Open(nil, data[NonceSize:], &nonce, pubKey, privKey)
}

/*
 *	Generate Encryption Keys
 */

// GenerateKeypair generates a public and a private key
func GenerateKeypair() (pubKey, privKey *[KeySize]byte, err error) {
	return box.GenerateKey(rand.Reader)
}

// GenerateKey generates a Key, by calculating the SHA-256 Hash for the given string
func GenerateKey(data string) *[KeySize]byte {

	var (
		h256 = sha256.New()
		res  = new([KeySize]byte)
		hash []byte
	)

	io.WriteString(h256, data)
	hash = h256.Sum(nil)

	for i := 0; i < 32; i++ {
		res[i] = hash[i]
	}
	return res
}

/*
 *	Securely set the key by reading from stdin
 */

// GenerateKeyStdin can be used to set the encryption key by reading it from stdin
func GenerateKeyStdin() *[KeySize]byte {

	var key *[KeySize]byte

	for key == nil {
		password, err := PasswordPrompt("enter password: ")
		if err != nil {
			fmt.Println(err)
		} else {
			repeat, err := PasswordPrompt("repeat password: ")
			if err != nil {
				fmt.Println(err)
			} else {
				if repeat == password {
					key = GenerateKey(password)
				} else {
					fmt.Println("passwords don't match! please try again")
				}
			}
		}
	}

	return key
}

// ReadKeyStdin reads the decryption key from stdin
func ReadKeyStdin() *[KeySize]byte {

	var key *[KeySize]byte

	for key == nil {
		pass, err := PasswordPrompt("enter password: ")
		if err != nil {
			fmt.Println(err)
		} else {
			key = GenerateKey(pass)
		}
	}

	return key
}

// PasswordPrompt reads a password from stdin without echoing the typed characters
func PasswordPrompt(prompt string) (password string, err error) {

	// create raw terminal and save state
	state, err := terminal.MakeRaw(0)
	if err != nil {
		log.Fatal(err)
	}

	// restore state when finished
	defer terminal.Restore(0, state)

	term := terminal.NewTerminal(os.Stdout, ">")

	// read pass
	password, err = term.ReadPassword(prompt)
	if err != nil {
		log.Fatal(err)
	}

	return
}

/*
 *	Hashes
 */

// MD5 returns an md5 hash of the given string
func MD5(text string) string {
	return hex.EncodeToString(MD5Data([]byte(text)))
}

// Sha256 generates a Sha256 for the given string
func Sha256(text string) []byte {
	return Sha256Data([]byte(text))
}

// hashFuncs

// MD5Data returns an md5 hash for the given data
func MD5Data(data []byte) []byte {

	// init md5 hasher
	hasher := md5.New()

	// write data into it
	hasher.Write(data)

	return hasher.Sum(nil)
}

// Sha1Data calculates the Sha1 for the given data
func Sha1Data(data []byte) []byte {

	// init sha256 hasher
	h := sha1.New()

	// write data into it
	h.Write(data)

	return h.Sum(nil)
}

// Sha256Data calculates the Sha256 for the given data
func Sha256Data(data []byte) []byte {

	// init sha256 hasher
	h256 := sha256.New()

	// write data into it
	h256.Write(data)

	return h256.Sum(nil)
}

// Sha512Data calculates the sha512 for the given data
func Sha512Data(data []byte) []byte {

	// init sha512 hasher
	h512 := sha512.New()

	// write data into it
	h512.Write(data)

	return h512.Sum(nil)
}

// HashFile calculates the hash for the contents of file
func HashFile(path string, hashFunc HashFunc) (string, error) {

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	if len(content) == 0 {
		return "", ErrEmptyFile
	}

	return hex.EncodeToString(hashFunc(content)), nil
}

// HashDir walks a directory and hashes all files inside
// afterwards all hashes are concatenated and hashed again
// this works because the order in which filepath.Walk walks the files is always the same
func HashDir(path string, hashFunc HashFunc) (string, error) {

	var (
		hashes = []string{}
		result string
	)

	err := filepath.Walk(path, func(name string, info os.FileInfo, err error) error {

		if err != nil {
			log.Fatal(err)
		}

		// ignore directories
		if !info.IsDir() {

			fmt.Println("hashing:", name)

			h, err := HashFile(name, hashFunc)
			if err != nil {
				return err
			}

			hashes = append(hashes, h)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	for _, h := range hashes {
		result += h
	}

	return hex.EncodeToString(hashFunc([]byte(result))), nil
}

// Base64 returns the base64 string for the given input
func Base64(text string) string {
	return base64.StdEncoding.EncodeToString([]byte(text))
}

/*
 *	Random
 */

// RandomString generates a length bytes long random string
func RandomString(length int) (string, error) {

	// init byteslice
	rb := make([]byte, length)

	// read from /dev/rand
	_, err := rand.Read(rb)
	if err != nil {
		return "", err
	}

	// return as string
	return base64.URLEncoding.EncodeToString(rb), nil
}

/*
 *	Integer Conversion
 */

// ConvertInt coverts an int into bin, hex, dec and oct
func ConvertInt(s string) (bin, oct, dec, hex string, err error) {

	// ParseInt interprets a string s in the given base (2 to 36) and returns the corresponding value i.
	// If base == 0, the base is implied by the string's prefix: base 16 for "0x", base 8 for "0", and base 10 otherwise.
	n, err := strconv.ParseInt(s, 0, 0)
	if err != nil {
		return "", "", "", "", err
	}

	return ToBin(n), ToOct(n), ToDec(n), ToHex(n), nil
}

// ToBin returns the binary representation of n
func ToBin(n int64) string {
	return strconv.FormatInt(n, 2)
}

// ToOct returns the octal representation of n
func ToOct(n int64) string {
	return strconv.FormatInt(n, 8)
}

// ToDec returns the decimal representation of n
func ToDec(n int64) string {
	return strconv.FormatInt(n, 10)
}

// ToHex returns the hex representation of n
func ToHex(n int64) string {
	return strconv.FormatInt(n, 16)
}
