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

// Build the config options based on the given options.
func buildConfigOptions(h string) ConfigOptions {
 	return ConfigOptions{
		ConfigFile:       filepath.Join(h, ".keeper", "ssh", "config.json"),
		ConfigFileBackup: filepath.Join(h, ".keeper", "config.json"),
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
func FetchPrivateKey(uid string) (string, error) {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
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
		return "", err
	}
	if len(records) == 0 {
		return "", fmt.Errorf("no records found for UID: %s", uid)
	}

	// GetFieldsByType returns an array of Field objects that match the 
	// specified type. In this case, we are filtering for fields of type 
	// "keyPair", as we only care about the private key.
	keys := records[0].GetFieldsByType("keyPair")[0]["value"].([]interface{})[0]
	privateKey := keys.(map[string]interface{})["privateKey"].(string)

	return privateKey, nil
}
