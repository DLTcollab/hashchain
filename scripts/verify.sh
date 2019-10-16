#!/bin/bash

if [ "${1}" == "-h" ]; then
    echo -e "Usage: \n\tscripts/verify.sh input_pdf anchor [algo] [range]"
    exit 0
fi

if ! [ -x "hashchain" ]; then
    echo "hashchain not found, execute make first"
    exit 1
fi

if ! [ -x "$(command -v exiftool)" ]; then
    echo "Install exiftool first"
    exit 1
fi

CONFIG="scripts/.exiftool_config"
# Determine if file exists or valid base64 encoded hash
if [ -e "${1}" ]; then
    QUERY=$(exiftool -config "${CONFIG}" -s -s -s -Hash "${1}") || exit 1
else
    TEST=$(echo "${1}" | base64 -d 2>&1 > /dev/null)
    [ $? != 0 ] && echo "Either file not exist or invalid base64 encoded string" && exit 1
    QUERY="${1}"
fi

# Determine if file exists or valid base64 encoded hash
if [ -e "${2}" ]; then
    ANCHOR=$(exiftool -config "${CONFIG}" -s -s -s -Hash "${2}")
else
    TEST=$(echo "${2}" | base64 -d 2>&1 > /dev/null)
    [ $? != 0 ] && echo "Either file not exist or invalid base64 encoded string" && exit 1
    ANCHOR="${2}"
fi

[ -z ${3} ] && ALGO="sha256" || ALGO="${3}"
[ -z ${4} ] && RANGE="10" || RANGE="${4}"

./hashchain verify "${ALGO}" "${QUERY}" "${ANCHOR}" "${RANGE}"
