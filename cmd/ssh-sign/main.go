package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Keeper-Security/git-ssh-sign/internal/sign"
	"github.com/Keeper-Security/git-ssh-sign/internal/vault"
)

func main() {
	/*
		When the gpg.format = ssh, git calls this program and will pass the
		following arguments:

			-Y sign -n git -f <KEY> /tmp/.git_signing_buffer_file

		The <KEY> is the user.signingkey value from the git config. This will
		be the UID of the record in the Vault.
		The /tmp/.git_signing_buffer_file is the file that contains the commit
		data that is to be signed.

		We need to:
		1. Fetch the private key from the Vault based on the UID.
		2. Sign the commit.
		3. Write the signature to a file. The file name should be the same as
		   the commit file but with a .sig extension.

		As long as the program returns a 0 exit code, git will continue with
		the commit, even if incorrectly signed. git wil not verify the
		signature at the time of commiting. If the exit code is non-zero,
		git will abort the commit.
	*/

	var action string
	var namespace string
	var sshUID string

	flag.StringVar(&action, "Y", "", "Action to perform") // Only 'sign' is currently supported.
	flag.StringVar(&namespace, "n", "", "Namespace")      // Only 'git' is supported.
	flag.StringVar(&sshUID, "f", "", "SSH Key UID")
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Println("This program is not intended to be run directly. It is called by git when signing commits.")
		os.Exit(1)
	}
	if namespace != "git" {
		fmt.Println("Only the 'git' namespace is supported.")
		os.Exit(1)
	}
	if action != "sign" {
		fmt.Println("Only the 'sign' action is supported.")
		os.Exit(1)
	}

	// `flag.Args` returns the non-flag arguments, only. In this case, the 
	// first and only argument should be the path to the file that contains the 
	// commit data.
	commitToSign := flag.Args()[0]

	privateKey, err := vault.FetchPrivateKey(sshUID)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	file, err := os.Open(commitToSign)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// To ensure that git can read the final signature file, we capture the
	// file permissions of the commit file to ensure the signature file has the
	// same permissions.
	fileinfo, err := os.Stat(commitToSign)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	fileMode := fileinfo.Mode()

	sig, err := sign.SignCommit(privateKey, file)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := os.WriteFile(fmt.Sprintf("%s.sig", commitToSign), sig, fileMode); err != nil {
		fmt.Println(err)
		os.Exit(1)
	} else {
		os.Exit(0)
	}
}
