package sign

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"

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

func Decode(b []byte) (*Signature, error) {
	// Borrowed from SigStore
	pemBlock, _ := pem.Decode(b)
	if pemBlock == nil {
		return nil, errors.New("unable to decode pem file")
	}

	if pemBlock.Type != "SSH SIGNATURE" {
		return nil, fmt.Errorf("wrong pem block type: %s. Expected SSH-SIGNATURE", pemBlock.Type)
	}

	// Now we unmarshal it into the Signature block
	sig := WrappedSig{}
	if err := ssh.Unmarshal(pemBlock.Bytes, &sig); err != nil {
		return nil, err
	}

	if sig.Version != 1 {
		return nil, fmt.Errorf("unsupported signature version: %d", sig.Version)
	}
	if string(sig.MagicHeader[:]) != magicHeader {
		return nil, fmt.Errorf("invalid magic header: %s", sig.MagicHeader[:])
	}
	if sig.Namespace != namespace {
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

func GetAllowedSigners(f *os.File) ([]AllowedSigner, error) {
	var allowedSigners []AllowedSigner
	scanner := bufio.NewScanner(f)
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

func VerifyFingerprints(principal []byte, pubKey ssh.PublicKey) error {

	fmt.Println(string(principal))
	fmt.Println(string(pubKey.Marshal()))

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
