# Sign Git commits with SSH Keys

Signing your git commits is an important security measure that verifies authorship, and ensures the integrity of committed content. Using cryptographic signatures demonstrates a commitment to the authenticity and security of your contributions, building trust among collaborators and protecting the repository from potential tampering and malicious code.

This integration allows developers to sign git commits with an SSH key stored in the Keeper Vault (via Keeper Secrets Manager) rather than using a key stored on disk.

## Requirements

Development requires:

- Git > 2.34.0
- Go > 1.20

Usage requires:

- [Keeper Secrets Manager](https://docs.keeper.io/secrets-manager/secrets-manager/overview)
  (KSM) [Enabled](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide)
- A Secrets Manager Application with read-only access to an SSH key

## KSM Set up

The integration expects a KSM Application Configuration file at either
`.config/keeper/ssh-sign.json` or
`ssh-sign.json`
relative to the user's home directory.

❗The KSM Application must have access to a Shared Folder that contains the SSH key.

### CLI-based Configuration

#### Scripts

The `configure-git.bash` script will build the integration and configure Git (globally) to use it.
The `Update-GitConfig.ps1` will do the same using PowerShell.

Run one or the other then skip ahead to [Repositories](#repositories)

#### Step-by-step

Alternatively, build the binary:

```shell
go build -o ssh-sign ./cmd/ssh-sign
```

Then set the `TOKEN` variable and run the Bash **or** PowerShell below to create the configuration:

```bash
TOKEN="One-time Access Token from Keeper"
CONFDIR="${HOME}/.config/keeper"
test -d $CONFDIR || mkdir -m 0700 -p "${CONFDIR}"
ksm init default --plain $TOKEN >| "${CONFDIR}/ssh-sign.json.new"
test $? -eq 0 && mv -f $CONFDIR/ssh-sign.json{.new,}
```

```PowerShell
$TOKEN = "One-time Access Token from Keeper"
if (!(Test-Path "${env:USERPROFILE}\.config\keeper")) {
    New-Item -Type Directory "${env:USERPROFILE}\.config\keeper"
}
$Config = if (ksm init default --plain $TOKEN) {
    Set-Content -Path "${env:USERPROFILE}\.config\keeper\ssh-sign.json" -Value $Config
}
```

Refer to the KSM [documentation](https://docs.keeper.io/secrets-manager/secrets-manager/about/one-time-token)
for help getting a One-time Access Token.

### UI-based Configuration

The KSM [configuration](https://docs.keeper.io/secrets-manager/secrets-manager/about/secrets-manager-configuration)
page walks through creating a KSM Application Configuration via the UI.

### Git Configuration

### Global

First, globally configure Git to use the binary to sign SSH format commits:

```shell
git config --global gpg.ssh.program path/to/ssh-sign
```

Afterward, `~/.gitconfig` should contain:

```ini
[gpg "ssh"]
    program = path/to/ssh-sign
```

### Repositories

Next, configure a Git repository to sign your commits using the SSH key from the Keeper Vault.

```shell
git config gpg.format ssh
git config user.signingkey SSH-Key-UID
```

Note that the executable expects the Git signing key to be the UID of the SSH key in the Keeper Vault.

The resulting Git configuration should look something like this:

```ini
[gpg]
    format = ssh
[user]
    signingKey = SSH-Key-UID
[gpg "ssh"]
    program = path/to/ssh-sign
```

## Usage

Simply run `git commit` with the `-S` switch to sign a commit!

You can confirm your commit has been signed with `git show --pretty=raw`.

### Automatic signing

To sign commits automatically for a repository, i.e., without the `-S` run:

```shell
git config commit.gpgsign true
```

## Troubleshooting

Git will execute `path/to/ssh-sign -Y sign -Y sign -n git -f SSH-Key-UID some-input.txt`.
It expects to write an output file with the same path as the input file with the extension `.sig`.
Thus to test whether the signing operation will work after creating the configuration,
run the aforementioned command on a file in a folder you can write to.

Thus, assuming `some-input.txt` exists in the current directory
then running the above will create a file named `some-input.txt.sig`
that will contain a signature, e.g.:

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

This module uses the built-in Golang tooling for building and testing:

```shell
# Run unit tests
go test ./...

# Build a local binary
go build -o ssh-sign.exe ./cmd/ssh-sign/main.go
```

Submit an [issue](https://github.com/Keeper-Security/git-ssh-sign/issues).
