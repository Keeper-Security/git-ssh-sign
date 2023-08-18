#!/bin/bash

test -n "$1" -a $# -eq 1 || {
    echo "Must supply the Keeper Secrets Manager Application Access Token as the first and only argument."
    exit 1
}
token=$1
declare -A commands=(
    ["git"]="Git"
    ["go"]="Go"
    ["ksm"]="Keeper Secrets Manager CLI"
)
for command in "${!commands[@]}"; do
    path=$(command -v "$command")
    test -n "$path" || {
        echo "Cannot find ${commands[$command]}."
        exit 1
    }
    eval "$command=$path"
done
config_dir="${HOME}/.config/keeper/ssh"

$ksm init default --plain $token >| config.json
if test $? -eq 0
then
    test -d "${config_dir}" || mkdir -m 0700 -p "${config_dir}"
    mv -f config.json "${config_dir}/config.json"
else
    echo "Failure executing '$ksm init default --plain $token'"
    rm -f config.json
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
