#!/bin/bash
umask 077

config_dir="${HOME}/.config/keeper"
token=$1
declare -A commands=(
    ["git"]="Git"
    ["go"]="Go"
    ["ksm"]="Keeper Secrets Manager CLI"
)

test -n "$1" -a $# -eq 1 || {
    echo "Must supply the Keeper Secrets Manager Application Access Token as the first and only argument."
    exit 1
}
for command in "${!commands[@]}"; do
    path=$(command -v "$command")
    test -n "$path" || {
        echo "Cannot find ${commands[$command]}."
        exit 1
    }
    eval "$command=$path"
done
$ksm init default --plain $token >| ssh-sign.json
if test $? -eq 0
then
    test -d "${config_dir}" || mkdir -p "${config_dir}"
    mv -f ssh-sign.json "${config_dir}/ssh-sign.json"
else
    echo "Failure executing '$ksm init default --plain $token'"
    rm -f ssh-sign.json
    exit 1
fi
for cmd in ./cmd/ssh-sign; do # because AI wrote it for me. 🤷
    name=$(basename $cmd)
    $go build -o "${name}" "${cmd}"
    test $? -eq 0 || {
        echo "Failure executing '$go build -o $name $cmd'"
        exit 1
    }
done
$git config --global gpg.ssh.program "$(pwd)/ssh-sign"
test $? -eq 0 || {
    echo "Failure executing '$git config --global gpg.ssh.program \"$(pwd)/${name}\"'"
    exit 1
}
