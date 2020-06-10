#!/bin/bash

if [ "${1}" == "-h" ]; then
    echo -e "Usage: \n\tscripts/sign.sh file seed [algo]"
    exit 0
fi

# Check if binaries exist
if ! [ -x "target/release/hashchain" ]; then
    echo "hashchain not found, execute \"cargo build --release\" first"
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

if ! [ -x "$(command -v b3sum)" ]; then
    echo "Install b3sum first (execute \"cargo install b3sum\")"
    exit 1
fi

# Variable initialization from argument
FILE="${1}"
CONFIG="scripts/.exiftool_config"
if ! [ -f "${CONFIG}" ]; then
    echo "Config file not found"
    exit 1
fi
[ -z ${3} ] && ALGO="blake3" || ALGO="${3}"
HASH=$(exiftool -config "${CONFIG}" -s -s -s -Hash "${FILE}") || exit 1
echo $HASH

# Generate hash 
if [ -z "${HASH}" ]; then
    SEED="${2}"
    if [ -z ${SEED} ]; then
        echo "Please specify a seed"
        exit 1
    fi
    NEW_HASH=$(target/release/hashchain create -a "${ALGO}" -s "${SEED}")
    echo "New hash: ${NEW_HASH}"
else 
    if [ "${ALGO}" == "blake3" ]; then 
        NEW_HASH=$(echo -n "${HASH}" | \
                openssl base64 -d -A | \
                b3sum --raw | \
                openssl base64)
    else
        NEW_HASH=$(echo -n "${HASH}" | \
                openssl base64 -d -A | \
                openssl dgst "-${ALGO}" -binary | \
                openssl base64)
    fi
    echo "New hash: ${NEW_HASH}"
fi

exiftool -config "${CONFIG}" -Hash="${NEW_HASH}" -overwrite_original "${FILE}"
