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


type Signature struct {
	signature *ssh.Signature
	pubKey    ssh.PublicKey
	hashAlg   string
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
	if sig.Namespace != "git" {
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
		signature: &sshSig,
		pubKey:    pk,
		hashAlg:   sig.HashAlgorithm,
	}, nil
}


func Verify(armoredSignature []byte, key []byte) (bool, error) {
	decodedSignature, err := Decode(armoredSignature)
	if err != nil {
		return false, err
	}

	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(key)
	if err != nil {
		return false, err
	}

	if decodedSignature.pubKey == publicKey {
		fmt.Println("Public keys match")
		return true, nil
	} else	{
		fmt.Println("Public keys do not match")
		return false, nil
	}

}

func GetAllowedSigners(f *os.File) ([]string, error) {
    var publicKeys []string
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        fields := strings.Fields(line)
        for index, field := range fields {
            if strings.HasPrefix(field, "ssh") {
				publicKeys = append(publicKeys, field+" "+fields[index+1])
				break
            }
        }
    }
    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return publicKeys, nil
}

func FindMatchingPrincipals(allowedSigners []string, signature *Signature) ([]string, error) {
	var matchingPrincipals []string
	for _, p := range allowedSigners {
		// Parse into wire format
		pak, _, _, _, err := ssh.ParseAuthorizedKey([]byte(p))
		if err != nil {
			return nil, err
		}	
		if bytes.Equal(signature.pubKey.Marshal(), pak.Marshal()) {
			matchingPrincipals = append(matchingPrincipals, p)
		}
	}
	return matchingPrincipals, nil
}