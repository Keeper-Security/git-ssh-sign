package sign

import (
	"strings"
	"testing"
)

var (
	// The following value was generated using the following command:
	// 		ssh-keygen -C test@example.com -t ed25519 -f test_key
	ed25519PrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCz+xopc6E4JvXVzyjCo+XGFuLePWU4641LMeAk1zkJ9AAAAJgzIeG6MyHh
ugAAAAtzc2gtZWQyNTUxOQAAACCz+xopc6E4JvXVzyjCo+XGFuLePWU4641LMeAk1zkJ9A
AAAEAF5dYQF/fBefn+Kn7M+1BjY6JZ/9TnOpeXQeMmNiv607P7GilzoTgm9dXPKMKj5cYW
4t49ZTjrjUsx4CTXOQn0AAAAEHRlc3RAZXhhbXBsZS5jb20BAgMEBQ==
-----END OPENSSH PRIVATE KEY-----		
`

	// The following value was generated using the following command:
	// 		ssh-keygen -C test@example -f test_key
	rsaPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
`
)

func TestSignCommit(t *testing.T) {
	data := strings.NewReader("test data")

	tests := []struct {
		name    string
		key     string
		wantErr bool
	}{
		{
			name:    "ED25519 Key",
			key:     ed25519PrivateKey,
			wantErr: false,
		},
		{
			name:    "RSA Key",
			key:     rsaPrivateKey,
			wantErr: false,
		},
		{
			name:    "Invalid Key",
			key:     "invalid key",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := SignCommit(tt.key, data)
			if (err != nil) != tt.wantErr {
				t.Errorf("TestSignCommit expected: %v, got: %v", tt.wantErr, err)
				return
			}
		})
	}
}
