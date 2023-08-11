# Sign Git commits with SSH Keys

Signing your git commits is important. It verifies authorship, ensures the integrity of committed content, prevents identity spoofing, and establishes non-repudiation. Using a cryptographic signature with your private key demonstrates a commitment to the authenticity and security of your contributions, building trust among collaborators and protecting the repository from potential tampering and malicious code.

This integration will let you sign git commits with an SSH key in your Keeper Vault (via Keeper Secrets Manager) rather than using a key stored on disk.

## Requirements

Development requires:

- Git > 2.34.0
- Go > 1.20
- [Keeper Secrets Manager Enabled](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide)

## Set up

### Secrets Manager Configuration

This integration uses the zero-knowledge Secrets Manager to fetch the SSH key from your vault. It expects to find the Secrets Manager configuration file at `.keeper/ssh/config.json` in the user's home directory for Windows and UNIX systems. If this configuration is not found, it will also check `.keeper/config.json` for an existing configuration from another integration. **The Secrets Manager application must have access to the shared folder in which your SSH key is stored**.

For help in setting up your application and obtaining your configuration file, you can find [detailed instructions here](https://docs.keeper.io/secrets-manager/secrets-manager/about/secrets-manager-configuration#creating-a-secrets-manager-configuration)

### Git Config

After successfully configuring Secrets Manager, you can now configure Git to sign your commits automatically. This can be done locally or globally, depending on your needs.

Four pieces of information are necessary for your config:

1. Tell git you want to sign all commits.
2. Tell git you want to use SSH signing over the default GPG signing.
3. Tell git the location of this integrations binary.
4. Tell git the UID of the SSH key to be used to sign.

We can do this locally with the following commands (add the `--global` flag to set these globally):

```shell
git config commit.gpgsign true
git config gpg.format ssh
git config gpg.ssh.program <path to this binary>
git config user.signingkey <SSH Key UID>
```

Your git config will now include these attributes:

```ini
[commit]
	gpgsign = true
[gpg]
	format = ssh
[user]
	signingKey = <SSH Key UID
[gpg "ssh"]
	program = path\to\sshsign.exe
```

## Usage

Git is now configured to automatically sign all commits, regardless of whether you use the terminal or an IDE interface to interact with git. It also removes the need to use the `-S` flag for commit signing. 

You can confirm your commit has been signed with `git show --pretty=raw`.

## Contirbuting

This module uses the built-in golang tooling for building and testing. For example:

```shell
# Run unit tests
go test ./...

# Build a local binary
go build -o ssh-sign.exe ./cmd/ssh-sign/main.go
```

You can submit issues and enhancement requests [here](https://github.com/Keeper-Security/git-ssh-sign/issues).