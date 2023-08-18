# Sign Git commits with SSH Keys

Signing your git commits is an important security measure that verifies authorship, and ensures the integrity of committed content. Using cryptographic signatures demonstrates a commitment to the authenticity and security of your contributions, building trust among collaborators and protecting the repository from potential tampering and malicious code.

This integration allows developers to sign git commits with an SSH key stored in the Keeper Vault (via Keeper Secrets Manager) rather than using a key stored on disk.

## Requirements

Development requires:

- Git > 2.34.0
- Go > 1.20

Usage requires:

- [Keeper Secrets Manager Enabled](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide)
- A Secrets Manager Application with read-only access to an SSH key

## Set up

### Secrets Manager Configuration

This integration uses the zero-knowledge [Keeper Secrets Manager](https://docs.keeper.io/secrets-manager/secrets-manager/overview) to fetch the SSH key from your vault. It expects to find the Secrets Manager configuration file at `.keeper/ssh/config.json` in the user's home directory for Windows and UNIX systems. If this configuration is not found, it will also check `.keeper/config.json` for an existing configuration from another integration. **The Secrets Manager application must have access to the shared folder in which your SSH key is stored**.

Here is some PowerShell to create the configuration from a One-time Access Token:

```PowerShell
$Token = "One-time Access Token from Keeper"
if (!(Test-Path "${env:USERPROFILE}\.keeper\.ssh")) {
    New-Item -Type Directory "${env:USERPROFILE}\.keeper\.ssh"
}
$Config = if (ksm init default --plain $Token) {
    Set-Content -Path "${env:USERPROFILE}\.keeper\ssh\config.json" -Value $Config
}
```

Or bash for Linux:

```bash
TOKEN="One-time Access Token from Keeper"
test -d "${HOME}/.keeper/ssh" || mkdir -m 0700 -p "${HOME}/.keeper/ssh"
ksm init default --plain $TOKEN >| "${HOME}/.keeper/ssh/config.json.new"
test $? -eq 0 && mv -f $HOME/.keeper/ssh/config.json{.new,}
```

Refer to the [Keeper documentation](https://docs.keeper.io/secrets-manager/secrets-manager/about/one-time-token)
for help getting a One-time Access Token.

### Git Config

After successfully configuring Keeper Secrets Manager,
configure Git to sign your commits using the SSH key in the Keeper Vault.
This can be done locally or globally.

Either way, Git needs the UID of the Secret containing the SSH key and the path to the ssh-sign executable.

Add `--global` after `git config` but before the name of the option in each of the commands below to make the configuration global:

```shell
git config gpg.format ssh
git config gpg.ssh.program <path to this binary>
git config user.signingkey <UID of the SSH Key>
```

Your git config will now include these attributes:

```ini
[gpg]
    format = ssh
[user]
    signingKey = <UID of the SSH Key>
[gpg "ssh"]
    program = path\to\ssh-sign.exe
```

## Usage

Simply run `git commit` with the `-S` switch to sign a commit!

You can confirm your commit has been signed with `git show --pretty=raw`.

### Automatic signing

To sign commits automatically, i.e., without the `-S`, set `commit.gpgsign` to `true`

```shell
git config commit.gpgsign true
```

## Troubleshooting

Git will execute `path\to\ssh-sign.exe -Y sign -Y sign -n git -f <Secret UID> <input file>`.
It expects to write an output file with the same path as the input file with the extension `.sig`.
Thus to test whether the signing operation will work after creating the configuration,
run the aforementioned command on a file in a folder you can write to.

If it works, `<input file>.sig` will exist and its contents will be a valid signature, e.g.:

```PEM
-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAZcAAAAHc3NoLXJzYQAAAAMBAAEAAAGBAL9iBpy9EFG4T9c3
...
...
...
rIalDYl8KKK+DPrwiF4KCKoovNN2xXu04ljxLH9O3byUcA==
-----END SSH SIGNATURE-----
```

## Contributing

This module uses the built-in Golang tooling for building and testing. For example:

```shell
# Run unit tests
go test ./...

# Build a local binary
go build -o ssh-sign.exe ./cmd/ssh-sign/main.go
```

You can submit issues and enhancement requests [here](https://github.com/Keeper-Security/git-ssh-sign/issues).
