# The path follows a pattern
# ./dist/BUILD-ID_TARGET/BINARY-NAME
source = ["./dist/git-ssh-sign-macos/git-ssh-sign"]
bundle_id = "github.com/Keeper-Security/git-ssh-sign/"

apple_id {
  username = "@env:secrets.AC_USERNAME"
  password = "@env:secrets.AC_PASSWORD"
}

sign {
  application_identity = "$@env:AC_APPID"
}
