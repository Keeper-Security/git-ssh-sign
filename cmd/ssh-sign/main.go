package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Keeper-Security/git-ssh-sign/internal/sign"
	"github.com/Keeper-Security/git-ssh-sign/internal/vault"
	"github.com/Keeper-Security/git-ssh-sign/internal/verify"
	"golang.org/x/crypto/ssh"
)

func main() {
	var action string
	var namespace string
	var inputFile string
	var signatureFile string
	var timestamp string
	var principal string

	flag.StringVar(&action, "Y", "", "Action to perform")
	flag.StringVar(&namespace, "n", "", "Namespace")
	flag.StringVar(&inputFile, "f", "", "SSH Key UID or allowed_signers file")
	flag.StringVar(&signatureFile, "s", "", "Signature file for verificaton")
	flag.StringVar(&timestamp, "Overify-time", "", "TODO")
	flag.StringVar(&principal, "I", "", "Principal to verify")
	flag.Parse()

	if len(os.Args) == 0 {
		fmt.Println("This program is not intended to be run directly. It is called by git when signing commits.")
		os.Exit(1)
	}

	// Only the 'git' namespace is supported.
	if namespace != "" && namespace != "git" {
		fmt.Println("Only the 'git' namespace is supported.")
		os.Exit(1)
	}

	if action == "sign" {
		/*
			When the gpg.format = ssh, git calls this program and will pass the
			following arguments:	
				-Y sign -n git -f <KEY> /tmp/.git_signing_buffer_file

			The <KEY> is the user.signingkey value from the git config. This 
			will be the UID of the record in the Vault.
			The /tmp/.git_signing_buffer_file is the file that contains the 
			commit data that is to be signed.

			We need to:
			1. Fetch the private key from the Vault based on the UID.
			2. Sign the commit.
			3. Write the signature to a file. The file name should be the same 
			as the commit file but with a .sig extension.

			As long as the program returns a 0 exit code, git will continue 
			with the commit, even if incorrectly signed. git wil not verify the
			signature at the time of commiting. If the exit code is non-zero,
			git will abort the commit.
		*/

		// `flag.Args` returns the non-flag arguments, only. In this case, the
		// first and only argument should be the path to the file that contains
		// the commit data.
		commitToSign := flag.Args()[0]
		if commitToSign == "" {
			fmt.Println("No commit file specified.")
			os.Exit(1)
		}

		keyPair, err := vault.FetchKeys(inputFile)
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
		// file permissions of the commit file to ensure the signature file has 
		// the same permissions.
		fileinfo, err := os.Stat(commitToSign)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fileMode := fileinfo.Mode()

		sig, err := sign.SignCommit(keyPair.PrivateKey, file)
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

	} else if action == "find-principals" {
		/*
			When verifying a signature locally, git will begin by collecting 
			all the verified signers from the allowed_signers file that match 
			the git commit passed. If one or more principals are found, hey are
			returned to stdout.
			
			The following arguments are passed to at this stage:
			-Y find-principals -f <allowed_signers_file> -s <signature_file> -Overify-time=<timestamp>
		*/
				
		allowedSigners, err := verify.GetAllowedSigners(inputFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		sig, err := verify.ParseSignatureFile(signatureFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		mp, err := verify.FindMatchingPrincipals(allowedSigners, sig)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else if len(mp) > 0 {
			// If one or more matching principals are found, they are returned
			// on standard output.
			for _, p := range mp {
				fmt.Println(p)
			}
			os.Exit(0)
		} else {
			fmt.Println("No matching principals found")
			os.Exit(1)
		}

	} else if action == "verify" {
		/*
			The second stage of the verification process is to verify the
			signature against the commit data. The fingerprints of the 
			principal are compared to the fingerprints of the public key in 
			the signature file. If they match, the signature is considered 
			verified. Successful verification by an authorized signer is 
			signalled by returning a zero exit status.

			The following arguments are passed to at this stage:
			-Y verify -n git -f <allowed_signers_file> -I <principal> -s <signature_file> -Overify-time=<timestamp>
		*/

		sig, err := verify.ParseSignatureFile(signatureFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}	

		if err := verify.VerifyFingerprints([]byte(principal), sig.PublicKey); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		allowedSigners, err := verify.GetAllowedSigners(inputFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		
		// Get email of the matching principal from the allowed_signers file.
		// This is used to display the email address of the signer in stdout.
		// Note: it is possible for multple principals to have the same email 
		// address associated with them. In this case, the first match is used.
		var principalEmail string
		for _, p := range allowedSigners {
			if p.PublicKey == principal {
				principalEmail = p.Email
				break
			}
		}

		// Parse the public key into SSH wire format
		pak, _, _, _, err := ssh.ParseAuthorizedKey([]byte(principal))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		pkType := strings.ToUpper(strings.Split(pak.Type(), "-")[1])
		fmt.Printf("Good \"%s\" signature for %s with %s key %s\n", namespace, principalEmail, pkType, ssh.FingerprintSHA256(pak))
		os.Exit(0)

	} else if action == "check-novalidate" {
		// If unable to verify the principal is in the allowed_signers file, 
		// git hecks the principal passed by git against the public key in the 
		// signature file. If they match, the signature is valid, but not 
		// verified.
		sig, err := verify.ParseSignatureFile(signatureFile)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}	

		pkType := strings.ToUpper(strings.Split(sig.PublicKey.Type(), "-")[1])
		fmt.Printf("Good \"%s\" signature with %s key %s\n", namespace, pkType, ssh.FingerprintSHA256(sig.PublicKey))
		fmt.Println("No principal matched")
		os.Exit(0)

	} else {
		// The only unsupported action is 'match-principals' as it is not used
		// by git.
		fmt.Println("Unsupported action. Only 'sign', 'find-principals', 'verify', and 'check-novalidate' are supported")
		os.Exit(1)
	}
}

