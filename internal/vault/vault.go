package vault

import (
	"fmt"
	"os"
	"path/filepath"

	ksm "github.com/keeper-security/secrets-manager-go/core"
)

type ConfigOptions struct {
	ConfigFile       string
	ConfigFileBackup string
}

type KeyPair struct {
	PrivateKey string
	PublicKey  string
	Passphrase string
}

// Build the config options based on the given options.
func buildConfigOptions(h string) ConfigOptions {
	return ConfigOptions{
		ConfigFile:       filepath.Join(h, ".config", "keeper", "ssh-sign.json"),
		ConfigFileBackup: filepath.Join(h, "ssh-sign.json"),
	}
}

// Find the config.json file
func getConfig(options ConfigOptions) (string, error) {
	// If the ConfigFile exists, use it, else check ConfigFileBackup. If
	// neither exist, returns an error.
	if _, err := os.Stat(options.ConfigFile); err == nil {
		return options.ConfigFile, nil
	} else if _, err := os.Stat(options.ConfigFileBackup); err == nil {
		return options.ConfigFileBackup, nil
	} else {
		return "", fmt.Errorf("config file not found")
	}
}

// Fetch a private key from the Vault via the Keeper Secrets Manager based on
// the UID in the git config.
func FetchKeys(uid string) (*KeyPair, error) {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// Get config file path to be used for the KSM
	config, err := getConfig(buildConfigOptions(homeDir))
	if err != nil || config == "" {
		fmt.Println(err)
		os.Exit(1)
	}

	sm := ksm.NewSecretsManager(
		&ksm.ClientOptions{Config: ksm.NewFileKeyValueStorage(config)})

	records, err := sm.GetSecrets([]string{uid})
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no records found for UID: %s", uid)
	}

	pubkey := ""
	privkey := ""
	if keys := records[0].GetFieldsByType("keyPair"); len(keys) > 0 {
		if kval, found := keys[0]["value"]; found {
			if sval, ok := kval.([]interface{}); ok && len(sval) > 0 {
				if mval, ok := sval[0].(map[string]interface{}); ok && len(mval) > 0 {
					if ipub, ok := mval["publicKey"]; ok {
						if pub, ok := ipub.(string); ok {
							pubkey = pub
						}
					}
					if ipriv, ok := mval["privateKey"]; ok {
						if priv, ok := ipriv.(string); ok {
							privkey = priv
						}
					}
				}
			}
		}
	}

	// public key can be extracted from private key, password is optional
	if privkey == "" {
		return nil, fmt.Errorf("no SSH keys found in UID: %s", uid)
	}

	password := ""
	if pass := records[0].GetFieldsByType("password"); len(pass) > 0 {
		if pval, found := pass[0]["value"]; found {
			if sval, ok := pval.([]interface{}); ok && len(sval) > 0 {
				if strval, ok := sval[0].(string); ok {
					password = strval
				}
			}
		}
	}

	return &KeyPair{
		PrivateKey: privkey,
		PublicKey:  pubkey,
		Passphrase: password,
	}, nil
}
