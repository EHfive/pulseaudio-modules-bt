#!/bin/bash
: ${1?"$(printf '%s\n' "Need a parameter! Which distribution would you like to build?" "$( for fn in *.Dockerfile; do printf '> %s\n' "${fn%.Dockerfile}"; done )")"}

ensure_that_has_permissions() {
    if ! sudo docker version
    then
        echo "Most likely you have no permisison to use docker! Aborting!" >&2
        exit 1
    fi
}

main() {
    local TGT="$1"
    (
        set -e
        sudo docker build -t "tmp.remove.${TGT}" -f "${TGT}.Dockerfile" .
        sudo docker run --rm --entrypoint /bin/bash "tmp.remove.${TGT}" -c 'tar -cf - /dist' | tar -x --no-same-owner
        echo "This script will not clean-up itself Docker Images!" >&2
    )
}

if [[ $EUID -eq 0 ]]; then
   echo "Script sould be run as a user! Not root!" >&2
   exit 1
fi
ensure_that_has_permissions
main "$@"