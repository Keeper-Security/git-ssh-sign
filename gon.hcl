source = ["dist/git-ssh-sign-macos_darwin_arm64/git-ssh-sign", "dist/git-ssh-sign-macos_darwin_arm64/git-ssh-sign"]
bundle_id = "github.com/Keeper-Security/git-ssh-sign/"

apple_id {
  username = "@env:AC_USERNAME"
  password = "@env:AC_PASSWORD"
}

sign {
  application_identity = "@env:AC_APPID"
}
