![GitHub](https://img.shields.io/github/license/Keeper-Security/git-ssh-sign)
![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/Keeper-Security/git-ssh-sign/test.yml)
![GitHub release (with filter)](https://img.shields.io/github/v/release/Keeper-Security/git-ssh-sign)


# Git commit signing with SSH Keys in Keeper

Sign Git commits using an SSH key stored in Keeper.

Signing Git commits is an important security measure that verifies authorship,
and ensures the integrity of the changes.
Just as importantly,
signing commits shows a commitment to authenticity and security,
helping to build trust in the community.

## Requirements

Development requires:

- Git > 2.34.0
- Go > 1.20

Usage requires:

- [Keeper Secrets Manager](https://docs.keeper.io/secrets-manager/secrets-manager/overview)
  (KSM) [enabled](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide)
- A Secrets Manager Application with read-only access to an SSH key

## KSM Set up

The integration expects a KSM Application Configuration file at either
`.config/keeper/ssh-sign.json` or
`ssh-sign.json`
relative to the user's home directory.
It must have access to a Shared Folder that contains the SSH key.
For help in obtaining a KSM configuration in JSON format, 
[follow these instructions](https://docs.keeper.io/secrets-manager/secrets-manager/about/secrets-manager-configuration#creating-a-secrets-manager-configuration).

> For help setting up the KSM and creating an application, head to the 
> [official docs](https://docs.keeper.io/secrets-manager/secrets-manager/quick-start-guide).

### CLI-based Configuration

#### Scripts

The `configure-git.sh` script will build the integration and configure Git (globally) to use it.
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

##### Notes

- The executable is standalone and can exist anywhere that Git can access.

- The KSM documentation details the process of getting a
  [One-time Access Token](https://docs.keeper.io/secrets-manager/secrets-manager/about/one-time-token).

### UI-based Configuration

The [Secrets Manager Configuration](https://docs.keeper.io/secrets-manager/secrets-manager/about/secrets-manager-configuration)
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

To sign commits automatically, i.e., without the `-S` run:

```shell
git config commit.gpgsign true
```

### Local verification

To verify signatures locally with a command such as `git log --show-signature -1`, you must create an `allowed_signers` file with trusted SSH public keys. Typically this file is saved either globally at `.ssh/allowed_signers` or in the local repo at `.git/allowed_signers`. The path to this file needs then to be added to your `.gitconfig` or `.git/config` file. 

```shell
git config gpg.ssh.allowedSignersFile path/to/file
```

Each line of your `allowed_signers` file should be a prinicipal of an authorized signing key. The line should start with the email address associated with the public key, seperated by a space.

```text
test@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEQvSrBv28KLAjYO7pD91prhlenrm3hZ4B7DdcB/4/H+
```

> The format of the allowed signers file is documented in full [here](https://www.man7.org/linux/man-pages/man1/ssh-keygen.1.html#:~:text=key%20was%20revoked.-,ALLOWED%20SIGNERS,-top). 

While it is correct syntax to have more than one email address associate with a single public key, it is not recommend or currently supported.

## Troubleshooting

Git will execute `path/to/ssh-sign -Y sign -Y sign -n git -f SSH-Key-UID some-input.txt`.
It expects to write an output file with the same path as the input file with the extension `.sig`.
So to test whether the signing operation will work after creating the configuration,
run the aforementioned command on a file in a folder you can write to.

As an example, assuming `some-input.txt` exists in the current directory
then running the above command exactly will create a file named `some-input.txt.sig`
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

Please read and refer to the [contribution guide](https://github.com/Keeper-Security/git-ssh-sign/blob/main/CONTRIBUTING.md) before making your first PR.

This module uses the built-in Golang tooling for building and testing:

```shell
# Run unit tests
go test ./...

# Build a local binary
go build -o ssh-sign ./cmd/ssh-sign/main.go
```

For bugs, changes, etc., please submit an [issue](https://github.com/Keeper-Security/git-ssh-sign/issues/new)!
