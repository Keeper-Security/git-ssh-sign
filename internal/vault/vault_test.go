package vault

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

var testHomeDir string

// Create a test directory for the config files used in subsequent unit tests.
func setup() string {
	var err error
	// MkDirTemp creates a directory and returns the path to it. The directory
	// name is prefixed with the given pattern and suffixed with a random 
	// string generated at initialization.
	testHomeDir, err = os.MkdirTemp(os.TempDir(), "keeper-test-")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return testHomeDir
}

// Remove the test directory and all of its contents.
func teardown(d string) {
	os.RemoveAll(d)
}

// Run setup code before and teardown code after all tests have completed.
func TestMain(m *testing.M) {
	dir := setup()
	code := m.Run()
	teardown(dir)
	os.Exit(code)
}

func TestBuildConfigOptions(t *testing.T) {
	configOptions := buildConfigOptions(testHomeDir)
	if configOptions.ConfigFile != filepath.Join(testHomeDir, ".config", "keeper", "ssh-sign.json") {
		t.Errorf("ConfigFile not built correctly")
	}
	if configOptions.ConfigFileBackup != filepath.Join(testHomeDir, "ssh-sign.json") {
		t.Errorf("ConfigFileBackup not built correctly")
	}
}

func TestGetConfig(t *testing.T) {
	testConfigFile, err := os.Create(filepath.Join(testHomeDir, "config.json"))
	if err != nil || testConfigFile == nil {
		t.Errorf("Unable to create temp config file")
	}

	configOptions := ConfigOptions{
		ConfigFile:       filepath.Join(testHomeDir, "config.json"),
		ConfigFileBackup: filepath.Join(testHomeDir, "config2.json"),
	}

	config, err := getConfig(configOptions)
	if err != nil {
		t.Errorf("Error getting config file: %v", err)
	}
	if config != configOptions.ConfigFile {
		t.Errorf("Error getting config file, expected %v, got %v", configOptions.ConfigFile, config)
	}

	// Subsequent unit tests test for the absence of the config file, so 
	// cleanup of the file needs to happen here instead of in the final 
	// teardown.
	testConfigFile.Close()
	err = os.Remove(testConfigFile.Name())
	if err != nil {
		t.Errorf("Error removing config file: %v", err)
	}

}

func TestGetConfigBackup(t *testing.T) {
	testBackupConfig, err := os.Create(filepath.Join(testHomeDir, "config2.json"))
	if err != nil || testBackupConfig == nil {
		t.Errorf("Unable to create temp backup config file")
	}

	configOptions := ConfigOptions{
		ConfigFile:       filepath.Join(testHomeDir, "config.json"),
		ConfigFileBackup: filepath.Join(testHomeDir, "config2.json"),
	}

	backupConf, err := getConfig(configOptions)
	if err != nil {
		t.Errorf("Error getting config file: %v", err)
	}
	if backupConf != configOptions.ConfigFileBackup {
		t.Errorf("Error getting config file, expected %v, got %v", configOptions.ConfigFile, backupConf)
	}

	// The next unit test tests for the absence of any config files, so 
	// cleanup of the file needs to happen here.
	testBackupConfig.Close()
	err = os.Remove(testBackupConfig.Name())
	if err != nil {
		t.Errorf("Error removing config file: %v", err)
	}
}

func TestGetConfigError(t *testing.T) {
	configOptions := ConfigOptions{
		ConfigFile:       filepath.Join(testHomeDir, "config.json"),
		ConfigFileBackup: filepath.Join(testHomeDir, "config2.json"),
	}

	_, err := getConfig(configOptions)
	if err == nil {
		t.Errorf("Expected an error getting config file, got nil")
	}
}
