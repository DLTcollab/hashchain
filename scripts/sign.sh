#!/bin/bash

if [ "${1}" == "-h" ]; then
    echo -e "Usage: \n\tscripts/sign.sh file seed [algo]"
    exit 0
fi

# Check if binaries exist
if ! [ -x "hashchain" ]; then
    echo "hashchain not found, execute make first"
    exit 1
fi

if ! [ -x "$(command -v openssl)" ]; then
    echo "Install openssl first"
    exit 1
fi

if ! [ -x "$(command -v exiftool)" ]; then
    echo "Install exiftool first"
    exit 1
fi

# Variable initialization from argument
FILE="${1}"
CONFIG="scripts/.exiftool_config"
if ! [ -f "${CONFIG}" ]; then
    echo "Config file not found"
    exit 1
fi
[ -z ${3} ] && ALGO="sha256" || ALGO="${3}"
HASH=$(exiftool -config "${CONFIG}" -s -s -s -Hash "${FILE}") || exit 1

# Generate hash 
if [ -z "${HASH}" ]; then
    SEED="${2}"
    if [ -z ${SEED} ]; then
        echo "Please specify a seed"
        exit 1
    fi
    NEW_HASH=$(./hashchain create -a "${ALGO}" -l 1 "${SEED}")
    echo "New hash: ${NEW_HASH}"
else 
    NEW_HASH=$(echo -n "${HASH}" | \
            openssl base64 -d -A | \
            openssl dgst "-${ALGO}" -binary | \
            openssl base64)
    echo "New hash: ${NEW_HASH}"
fi

exiftool -config "${CONFIG}" -Hash="${NEW_HASH}" -overwrite_original "${FILE}"
