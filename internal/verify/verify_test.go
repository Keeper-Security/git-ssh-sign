package verify

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/Keeper-Security/git-ssh-sign/internal/sign"
	"golang.org/x/crypto/ssh"
)

var (
	// The following value was generated using the following command:
	// 		ssh-keygen -C test@example.com -t ed25519 -f test_key
	ed25519PrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBEL0qwb9vCiwI2Du6Q/daa4ZXp65t4WeAew3XAf+Px/gAAAJjrEknt6xJJ
7QAAAAtzc2gtZWQyNTUxOQAAACBEL0qwb9vCiwI2Du6Q/daa4ZXp65t4WeAew3XAf+Px/g
AAAECc4rBgLCDFFGGM1TOtV5VpkGTERsYw/237NqOB/AtCOEQvSrBv28KLAjYO7pD91prh
lenrm3hZ4B7DdcB/4/H+AAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----		
`

	ed25519PublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEQvSrBv28KLAjYO7pD91prhlenrm3hZ4B7DdcB/4/H+"

	// The following value was generated using the following command:
	// 		ssh-keygen -C test@example -f test_key
	rsaPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAw/EMR4HWC+2EHMuxzLGJ/yXxQH8CVjauZwpJIH5KO2wPjUHkHDcy
4RyKM+U3wh7seSm/h/pm2+JmGQ2NHk9s4MuUG2ZCaYIHhcOpnU9p9g4L6H/4CVC7AwYemW
5LUU5cJEFw4NDiU/1tggqOSfuQ6F2lXM8OvDpk3e9o9PP6eegbG1ySu0VKVCvpt4JoX5jE
JezOUAlVRHttj6V7uwDFepZqspunKnKjK5mp9vrM3AL4ajvkzWQSiN8yPEV2RyBxUkkDJV
zAakoZvCJMp5kVcvJBcvSu7ZIzaBpX4g/8ou9woWhmS4cdnfP3BZuRYEcxGwOOXzlQtAzH
jSqUaBXo2GR63pMIrAHCKGdhtm7sWuocz8QAtuHGeRf3hHlZp/i4/LVkj0Ue6ewBDFpzar
dIDYWOsL/ogMJEnL10UgSsL5zkCFyhs9omLkcoY7gJL6yQ36TsOfGzSC2k0c3kUAG0eVJ7
FETeJyCjoOf4qD5EfOXOA699fw5gDk7bXcOEp3tBAAAFiBmnbWsZp21rAAAAB3NzaC1yc2
EAAAGBAMPxDEeB1gvthBzLscyxif8l8UB/AlY2rmcKSSB+SjtsD41B5Bw3MuEcijPlN8Ie
7Hkpv4f6ZtviZhkNjR5PbODLlBtmQmmCB4XDqZ1PafYOC+h/+AlQuwMGHpluS1FOXCRBcO
DQ4lP9bYIKjkn7kOhdpVzPDrw6ZN3vaPTz+nnoGxtckrtFSlQr6beCaF+YxCXszlAJVUR7
bY+le7sAxXqWarKbpypyoyuZqfb6zNwC+Go75M1kEojfMjxFdkcgcVJJAyVcwGpKGbwiTK
eZFXLyQXL0ru2SM2gaV+IP/KLvcKFoZkuHHZ3z9wWbkWBHMRsDjl85ULQMx40qlGgV6Nhk
et6TCKwBwihnYbZu7FrqHM/EALbhxnkX94R5Waf4uPy1ZI9FHunsAQxac2q3SA2FjrC/6I
DCRJy9dFIErC+c5AhcobPaJi5HKGO4CS+skN+k7Dnxs0gtpNHN5FABtHlSexRE3icgo6Dn
+Kg+RHzlzgOvfX8OYA5O213DhKd7QQAAAAMBAAEAAAGBALaGw8ORBU4TMfCJJ9XgxQYz2C
sWpZyeT5SZFkn4mzoDjfEuokpOeU0OgweYzXo9yFeONmd7MXo/ypAn+X90yZ4Wxp9HgTI7
+Ln47PYn1jNqHlm1a99xnuRQPQz8m5jgACGd/ILQ0yUefXaYUrhEalardbGhCL77Pp8nuI
QHCxuoxieU8vMUtwr15UAXcRcsffw+Pmp8ZzvmJsebhklLjKqHmFlNekmmhK3G9XenZlLF
SZfct2VFhaaPFILkyiuz4XjYPNUFaAcMkVPwo0SlsR3w0trijIqTgGa0Yw2JmgjDatYbQW
MIFfti7zi1wPYTmDOxO2fMu7/RnjCPTyl0lBYZsXT3jNKg/EwFXa+0CgKOTKFjDxk/DE3p
juWhQGJIMEKDNTFcjAfGkwi+6mmKmeR/O4wCCWvwLPtAqWNF9XddMXKg792D/EKEi1dts9
3RDXzgOGyJ5h0tLeinxzSAoErh8YdR18/LIlAFhmz08IgkZlXoBeZESKgH5TiCBgNs4QAA
AMB7yqZAeR1cpYX5Z/2/nkEorTL/aPm/rA/IwPaKJkuXzKJvbE4VpuDDZylJP6VqyUMx3u
8zpjBDuzO4MoXtusragYiZPENmjFE5lRLzDy8N68uRJ+I9RtCdrDLn6WBXedlozs1v7g1k
/G8Eqk32pPuBQmY8Um0s/dCGE8bFxmV/SsU99IyIA1HfDxUXecepB9BBn/HKhxxOSkuYrb
VHoyKNx9jOXU4ELR0tI1/tfyidQWCg0seleWfD9f1mPnoClfEAAADBAPnmbj40CdPQk/Nf
mDMjW/Z0NI27CmoZKctRwu2En7Pik9LsOimLSIkGrn12LDDxePQXqvwV+vMl+ikLULBMpl
HWVGR4+lmxay4vKx7zI+nZkqTrsd4dMzo1dR3eZaZlYs1D4B3tARhN5upIZU7VjR94nEKQ
r4GD2jJWJjmRFRAXHsLimaX/zCBevR/iadh1amuQlSPiuciEGzwQeEojUbwzGR3qjRMn1P
FdBZeqZclR3N66/l/GeWxIG7siJtopZQAAAMEAyLlxVItGs19QH/SzV654FLvoB37EYt2a
7PbVtVC3sRNn3cPWdna93I6SPiwl14RJ7iwB4GHot6mHrmMlhedpWByDn7HNqzILKJtrUE
hf4Bwf/qYnfuWUBYVwsz26XgKIKpTZ6Gr0jBLZHWhl+0D2SRC2XnYd3/9E9IpKiBAOMKlz
uJ1Awx7wJYmxfF9Q6Vj3v7o/B8IPA5xxA1H1AglnzESKtRUwm1PAOPDLSQWaMgj5erTLAt
MQUjv26NIZPFqtAAAADHRlc3RAZXhhbXBsZQECAwQFBg==
-----END OPENSSH PRIVATE KEY-----
`

	rsaPublicKey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDD8QxHgdYL7YQcy7HMsYn/JfFAfwJWNq5nCkkgfko7bA+NQeQcNzLhHIoz5TfCHux5Kb+H+mbb4mYZDY0eT2zgy5QbZkJpggeFw6mdT2n2Dgvof/gJULsDBh6ZbktRTlwkQXDg0OJT/W2CCo5J+5DoXaVczw68OmTd72j08/p56BsbXJK7RUpUK+m3gmhfmMQl7M5QCVVEe22PpXu7AMV6lmqym6cqcqMrman2+szcAvhqO+TNZBKI3zI8RXZHIHFSSQMlXMBqShm8IkynmRVy8kFy9K7tkjNoGlfiD/yi73ChaGZLhx2d8/cFm5FgRzEbA45fOVC0DMeNKpRoFejYZHrekwisAcIoZ2G2buxa6hzPxAC24cZ5F/eEeVmn+Lj8tWSPRR7p7AEMWnNqt0gNhY6wv+iAwkScvXRSBKwvnOQIXKGz2iYuRyhjuAkvrJDfpOw58bNILaTRzeRQAbR5UnsURN4nIKOg5/ioPkR85c4Dr31/DmAOTttdw4Sne0E="

)

var (
	allowedSigners = []AllowedSigner{
		{
			Email: "test@example.com",
			PublicKey: ed25519PublicKey,
		},
		{
			Email: "test@example.com",
			PublicKey: rsaPublicKey,
		},
	}
)

func TestFindMatchingPrincipals(t *testing.T) {
	principal, _, _, _, err := ssh.ParseAuthorizedKey([]byte(allowedSigners[0].PublicKey))
	if err != nil {
		t.Fatalf("Failed to parse test principal: %v", err)
	}
	
	sig := &Signature{
        PublicKey: principal,
    }

    // Find matching principals
    matchingPrincipals, err := FindMatchingPrincipals(allowedSigners, sig)
    if err != nil {
        t.Fatalf("FindMatchingPrincipals returned an error: %v", err)
    }

    // Check that the correct principals were found
    expectedPrincipals := []string{allowedSigners[0].PublicKey}
    if !reflect.DeepEqual(matchingPrincipals, expectedPrincipals) {
        t.Errorf("FindMatchingPrincipals returned %v, expected %v", matchingPrincipals, expectedPrincipals)
    }
}

func TestGetAllowedSigners(t *testing.T) {
    // Create a test file
    testFile := "testfile.txt"
    f, err := os.Create(testFile)
    if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
    }
    fmt.Fprintln(f, allowedSigners[0].Email, allowedSigners[0].PublicKey)
    fmt.Fprintln(f, allowedSigners[1].Email, allowedSigners[1].PublicKey)
	defer f.Close()
	defer os.Remove(testFile)

    // Get the AllowedSigners from the test file
    as, err := GetAllowedSigners(testFile)
    if err != nil {
        t.Fatalf("GetAllowedSigners returned an error: %v", err)
    }

    if !reflect.DeepEqual(as, allowedSigners) {
        t.Errorf("GetAllowedSigners returned %v, expected %v", as, allowedSigners)
    }
}

func TestVerifyFingerprints(t *testing.T) {
    // Create a test principal and public key
    principal := []byte(ed25519PublicKey)
    pubKey, _, _, _, err := ssh.ParseAuthorizedKey(principal)
    if err != nil {
        t.Fatalf("Failed to parse test principal: %v", err)
    }

    if err := VerifyFingerprints(principal, pubKey); err != nil {
        t.Errorf("VerifyFingerprints returned an error: %v", err)
    }
}


func TestVerifySignature(t *testing.T) {
	data := []byte("Hello, git-ssh-sign!")
	otherSSHPublicKey := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB2ZzQ8p3/T61CSfhzH9IDhvkLP95OZ9vjwFOFOWH64Y test@example.com"

	for _, tt := range []struct {
		name string
		pub  string
		priv string
	}{
		{
			name: "rsa",
			pub:  rsaPublicKey,
			priv: rsaPrivateKey,
		},
		{
			name: "ed25519",
			pub:  ed25519PublicKey,
			priv: ed25519PrivateKey,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt

			s, err := ssh.ParsePrivateKey([]byte(tt.priv))
			if err != nil {
				t.Fatal(err)
			}

			as, ok := s.(ssh.AlgorithmSigner)
			if !ok {
				t.Fatal(err)
			}

			signature, err := sign.NewSignature(as, bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}

			decodedSignature, err := Decode(sign.Armor(signature, s.PublicKey()))
			if err != nil {
				t.Fatal(err)
			}

			// Verify the principal is the same as the one used to sign the data
			if err := VerifyFingerprints([]byte(tt.pub), decodedSignature.PublicKey); err != nil {
				t.Error(err)
			}

			// Should fail with a different principal used to sign the data
			if err := VerifyFingerprints([]byte(otherSSHPublicKey), decodedSignature.PublicKey); err == nil {
				t.Error("expected error!")
			}
		})
	}

}


func TestValidDecode(t *testing.T) {
	data := []byte("Hello, decode function!")

	for _, tt := range []struct {
		name string
		pub  string
		priv string
	}{
		{
			name: "rsa",
			pub:  rsaPublicKey,
			priv: rsaPrivateKey,
		},
		{
			name: "ed25519",
			pub:  ed25519PublicKey,
			priv: ed25519PrivateKey,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt

			s, err := ssh.ParsePrivateKey([]byte(tt.priv))
			if err != nil {
				t.Fatal(err)
			}

			as, ok := s.(ssh.AlgorithmSigner)
			if !ok {
				t.Fatal(err)
			}

			signature, err := sign.NewSignature(as, bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}

			// Check that Decode returns no error when given a valid signature
			_, err = Decode(sign.Armor(signature, s.PublicKey()))
			if err != nil {
				t.Fatalf("Decode returned an error: %v", err)
			}
		})
	}

}

func TestInvalidDecode(t *testing.T) {
	dataFile := "invalid-decode.txt"
	f, err := os.Create(dataFile)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	fmt.Fprintln(f, "Hello, decode function!")
	defer f.Close()
	defer os.Remove(dataFile)

	for _, tt := range []struct {
		name string
		pub  string
		priv string
	}{
		{
			name: "rsa",
			pub:  rsaPublicKey,
			priv: rsaPrivateKey,
		},
		{
			name: "ed25519",
			pub:  ed25519PublicKey,
			priv: ed25519PrivateKey,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt := tt

			s, err := ssh.ParsePrivateKey([]byte(tt.priv))
			if err != nil {
				t.Fatal(err)
			}

			as, ok := s.(ssh.AlgorithmSigner)
			if !ok {
				t.Fatal(err)
			}

			sig, err := sign.NewSignature(as, f)
			if err != nil {
				t.Fatal(err)
			}

			// Wrap the signature in a MessageWrapper with an invalid namespace
			swn := sign.WrappedSig{
				Version:       1,
				PublicKey:     string(tt.pub),
				Namespace:     "file",
				HashAlgorithm: sign.DefaultHashAlgorithm,
				Signature:     string(ssh.Marshal(sig)),
			}
		
			copy(swn.MagicHeader[:], sign.MagicHeader)
		
			swnPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "SSH SIGNATURE",
				Bytes: ssh.Marshal(sig),
			})

			// Check that Decode returns an error when given an invalid 
			// signature
			_, err = Decode(swnPEM)
			if err == nil {
				t.Fatalf("Decode returned no error, expected error")
			}

			// Wrap the signature in a MessageWrapper with an invalid hash
			swh := sign.WrappedSig{
				Version:       1,
				PublicKey:     string(tt.pub),
				Namespace:     sign.Namespace,
				HashAlgorithm: "invalid",
				Signature:     string(ssh.Marshal(sig)),
			}

			copy(swh.MagicHeader[:], sign.MagicHeader)
		
			swhPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "SSH SIGNATURE",
				Bytes: ssh.Marshal(sig),
			})
			_, err = Decode(swhPEM)
			if err == nil {
				t.Fatalf("Decode returned no error, expected error")
			}

			// Wrap the signature in a MessageWrapper with an invalid magic 
			// header
			swmh := sign.WrappedSig{
				Version:       1,
				PublicKey:     string(tt.pub),
				Namespace:     sign.Namespace,
				HashAlgorithm: sign.DefaultHashAlgorithm,
				Signature:     string(ssh.Marshal(sig)),
			}

			copy(swmh.MagicHeader[:], "INVALID")
		
			swmhPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "SSH SIGNATURE",
				Bytes: ssh.Marshal(sig),
			})
			_, err = Decode(swmhPEM)
			if err == nil {
				t.Fatalf("Decode returned no error, expected error")
			}

			// Wrap the signature in a MessageWrapper with an invalid version
			swv := sign.WrappedSig{
				Version:       1000,
				PublicKey:     string(tt.pub),
				Namespace:     sign.Namespace,
				HashAlgorithm: sign.DefaultHashAlgorithm,
				Signature:     string(ssh.Marshal(sig)),
			}

			copy(swv.MagicHeader[:], sign.MagicHeader)
		
			swvPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "SSH SIGNATURE",
				Bytes: ssh.Marshal(sig),
			})
			_, err = Decode(swvPEM)
			if err == nil {
				t.Fatalf("Decode returned no error, expected error")
			}


		})
	}

}
