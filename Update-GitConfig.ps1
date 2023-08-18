<#
.SYNOPSIS
    Configure Git to use an SSH Key in Keeper Secrets Manager to sign commits
#>
param (
    # Keeper Secrets Manager One-time Access Token"
    [string]$AccessToken,
    [string]$ConfigurationDirectory = "${env:USERPROFILE}\.config\keeper\ssh"
)
#region Initialize KSM configuration
Invoke-Command { ksm init default --plain $args } -ArgumentList $AccessToken |
Set-Variable ConfigJson
if (!(Test-Path $ConfigurationDirectory)) {
    New-Item -Type Directory $ConfigurationDirectory
}
Set-Content "${ConfigurationDirectory}\config.json" -Value $ConfigJson
#endregion
#region build ssh-sign.exe
foreach ($Command in (Get-ChildItem -Path .\cmd)) {
    Invoke-Command { go build -o $args } -ArgumentList "$($Command.Name).exe", $Command.FullName
}
#endregion
#region Configure Git to use ssh-sign.exe
git config --global gpg.ssh.program ((Get-Item 'ssh-sign.exe').FullName.Replace('\\', '/'))
#endregion
