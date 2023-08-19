<#
.SYNOPSIS
    Configure Git to use an SSH Key in Keeper Secrets Manager to sign commits
#>
param (
    # Keeper Secrets Manager One-time Access Token"
    [Parameter(Mandatory)][string]$AccessToken,
    [string]$ConfigurationDirectory = "${env:USERPROFILE}\.config\keeper",
    [string]$Ksm = (Get-Command 'ksm' | Select-Object -ExpandProperty Source),
    [string]$Go = (Get-Command 'go' | Select-Object -ExpandProperty Source)
)
#region Initialize KSM configuration
& $Ksm init default --plain $AccessToken | Set-Variable ConfigJson
if (!(Test-Path $ConfigurationDirectory)) {
    New-Item -Type Directory $ConfigurationDirectory
}
Set-Content "${ConfigurationDirectory}\ssh-sign.json" -Value $ConfigJson
#endregion
#region build ssh-sign.exe
foreach ($Command in (Get-ChildItem -Path .\cmd)) {
    & $Go build -o "$($Command.Name).exe" $Command
}
#endregion
#region Configure Git to use ssh-sign.exe
git config --global gpg.ssh.program "$(Get-Item 'ssh-sign.exe')"
#endregion
