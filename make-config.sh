#!/bin/bash

digits=6

if [ "${1}" = "" ]; then
	echo "Syntax: ${0} config [6|7|8]"
	exit 1
fi

if [ "${2}" != "" ]; then
	digits="${2}"
fi

secret="$(./oath-exec -g 20)"

if [ "$?" != "0" ]; then
	echo "Can't generate secret!"
	exit 1
fi

umask 0077

echo "type=TOTP" >$1
echo "secret=${secret}" >>$1
echo "digits=${digits}" >>$1

name="$(basename "${1}")"

qrencode -o - -t ANSI "otpauth://totp/${name}?secret=${secret}&digits=${digits}"
if [ "$?" != "0" ]; then
	echo "qrencode -o - -t ANSI \"otpauth://totp/${name}?secret=${secret}&digits=${digits}\""
fi
