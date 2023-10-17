package sign

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"io"
)

/* 
	The code in this module is heavily based on the great work done by the 
	sigstore/rekor project: https://github.com/sigstore/rekor/
*/

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig#L81
type MessageWrapper struct {
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Hash          string
}

// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig#L34
type WrappedSig struct {
	MagicHeader   [6]byte
	Version       uint32
	PublicKey     string
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     string
}

const (
	MagicHeader          = "SSHSIG"
	DefaultHashAlgorithm = "sha512"
	Namespace            = "git"
)

// Create an Armored (PEM) Signature
func Armor(sshSig *ssh.Signature, pubKey ssh.PublicKey) []byte {
	sig := WrappedSig{
		Version:       1,
		PublicKey:     string(pubKey.Marshal()),
		Namespace:     Namespace,
		HashAlgorithm: DefaultHashAlgorithm,
		Signature:     string(ssh.Marshal(sshSig)),
	}

	copy(sig.MagicHeader[:], MagicHeader)

	enc := pem.EncodeToMemory(&pem.Block{
		Type:  "SSH SIGNATURE",
		Bytes: ssh.Marshal(sig),
	})
	return enc
}

// Create a signature for the given data using the given signer.
func NewSignature(signer ssh.AlgorithmSigner, data io.Reader) (*ssh.Signature, error) {
	hf := sha512.New()
	if _, err := io.Copy(hf, data); err != nil {
		return nil, err
	}
	mh := hf.Sum(nil)

	sp := MessageWrapper{
		Namespace:     Namespace,
		HashAlgorithm: DefaultHashAlgorithm,
		Hash:          string(mh),
	}

	dataMessageWrapper := ssh.Marshal(sp)
	dataMessageWrapper = append([]byte(MagicHeader), dataMessageWrapper...)

	// ssh-rsa is not supported for RSA keys:
	// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig#L71
	// We can use the default value of "" for other key types though.
	algo := ""
	if signer.PublicKey().Type() == ssh.KeyAlgoRSA {
		algo = ssh.KeyAlgoRSASHA512
	}
	sig, err := signer.SignWithAlgorithm(rand.Reader, dataMessageWrapper, algo)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Sign a commit(data) using the given private key.
func SignCommit(sshPrivateKey string, data io.Reader) ([]byte, error) {
	s, err := ssh.ParsePrivateKey([]byte(sshPrivateKey))
	if err != nil {
		return nil, err
	}

	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return nil, err
	}

	sig, err := NewSignature(as, data)
	if err != nil {
		return nil, err
	}

	armored := Armor(sig, s.PublicKey())
	return armored, nil
}
