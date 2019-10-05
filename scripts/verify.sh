#!/bin/sh

if ! [ -x "hashchain" ]; then
    echo "hashchain not found, execute make first"
    exit 1
fi

if ! [ -x "$(command -v exiftool)" ]; then
    echo "Install exiftool first"
    exit 1
fi

CONFIG="scripts/.exiftool_config"
QUERY=$(exiftool -config "${CONFIG}" -s -s -s -Hash "${1}") || exit 1
ANCHOR=$(exiftool -config "${CONFIG}" -s -s -s -Hash "${2}") || exit 1
[ -z ${3} ] && ALGO="sha256" || ALGO="${3}"
[ -z ${4} ] && RANGE="10" || RANGE="${4}"

./hashchain verify "${ALGO}" "${QUERY}" "${ANCHOR}" "${RANGE}"
