package verify

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"strings"

	"github.com/Keeper-Security/git-ssh-sign/internal/sign"
	"golang.org/x/crypto/ssh"
)

type AllowedSigner struct {
	Email     string
	PublicKey string
}

type Signature struct {
	Signature     *ssh.Signature
	PublicKey     ssh.PublicKey
	HashAlgorithm string
}

var supportedHashAlgorithms = map[string]func() hash.Hash{
	"sha256": sha256.New,
	"sha512": sha512.New,
}

// Decodes a PEM encoded signature into a Signature struct. If invalid or 
// unsupported data is found, an error is returned, even if the signature is 
// valid for other use cases ourside of the restrictions of this program. 
func Decode(b []byte) (*Signature, error) {
	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
		return nil, errors.New("unable to decode pem file")
	}

	if pemBlock.Type != "SSH SIGNATURE" {
		return nil, fmt.Errorf("wrong pem block type: %s. Expected SSH-SIGNATURE", pemBlock.Type)
	}

	// Unmarshal into the Signature block
	sig := sign.WrappedSig{}
	if err := ssh.Unmarshal(pemBlock.Bytes, &sig); err != nil {
		return nil, err
	}

	// Validation of the Signature block is done before we can unpack the 
	// Signature and PublicKey blocks. This ensures that we don't unpack 
	// malicious, invalid, or unsupported data. Instead, we can return an
	// error before we do any unpacking.
	if sig.Version != 1 {
		return nil, fmt.Errorf("unsupported signature version: %d", sig.Version)
	}
	if string(sig.MagicHeader[:]) != sign.MagicHeader {
		return nil, fmt.Errorf("invalid magic header: %s", sig.MagicHeader[:])
	}
	if sig.Namespace != sign.Namespace {
		return nil, fmt.Errorf("invalid signature namespace: %s", sig.Namespace)
	}
	if _, ok := supportedHashAlgorithms[sig.HashAlgorithm]; !ok {
		return nil, fmt.Errorf("unsupported hash algorithm: %s", sig.HashAlgorithm)
	}

	// Now we can unpack the Signature and PublicKey blocks
	sshSig := ssh.Signature{}
	if err := ssh.Unmarshal([]byte(sig.Signature), &sshSig); err != nil {
		return nil, err
	}

	pk, err := ssh.ParsePublicKey([]byte(sig.PublicKey))
	if err != nil {
		return nil, err
	}

	return &Signature{
		Signature:     &sshSig,
		PublicKey:     pk,
		HashAlgorithm: sig.HashAlgorithm,
	}, nil
}

// Finds matching principals for the given signature.
func FindMatchingPrincipals(as []AllowedSigner, signature *Signature) ([]string, error) {
	var matchingPrincipals []string
	for _, p := range as {
		// Parse into wire format
		pak, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p.PublicKey))
		if err != nil {
			return nil, err
		}
		if bytes.Equal(signature.PublicKey.Marshal(), pak.Marshal()) {
			matchingPrincipals = append(matchingPrincipals, p.PublicKey)
		}
	}
	return matchingPrincipals, nil
}

// Parse a given file and returns a slice of AllowedSigners.
func GetAllowedSigners(f string)([]AllowedSigner, error) {
	asf, err := os.Open(f)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer asf.Close()

	var allowedSigners []AllowedSigner
	scanner := bufio.NewScanner(asf)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		as := AllowedSigner{
			Email: fields[0],
			PublicKey: fields[1]+ " " + fields[2],
		}
		allowedSigners = append(allowedSigners, as)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return allowedSigners, nil
}

// Parse a given file and returns a Signature struct.
func ParseSignatureFile(signatureFile string) (*Signature, error) {
	signature, err := os.Open(signatureFile)
	if err != nil {
		return nil, err
	}
	defer signature.Close()

	sigBytes, err := io.ReadAll(signature)
	if err != nil {
		return nil, err
	}

	sig, err := Decode(sigBytes)
	if err != nil {
		return nil, err
	}

	return sig, nil
}

// Compares the fingerprint of the principal with the public key in the 
// signature.
func VerifyFingerprints(principal []byte, pubKey ssh.PublicKey) error {
	// Parse into wire format
	pak, _, _, _, err := ssh.ParseAuthorizedKey(principal)
	if err != nil {
		return err
	}

	principalHash := []byte(ssh.FingerprintSHA256(pak))
	pubKeyHash := []byte(ssh.FingerprintSHA256(pubKey))

	if bytes.Equal(principalHash, pubKeyHash) {
		return nil
	}
	return errors.New("fingerprint does not match")
}
