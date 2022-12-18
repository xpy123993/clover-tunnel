#!/bin/bash

SRC_FOLDER=.
CERT_FOLDER=tokens
OUTPUT_FOLDER=releases
VERSION_NUMBER=${1:-debug}
CA_SUBJECT="/C=US/ST=CA/L=Sunnyvale/O=Tunnel Service./CN=Yukino Root CA"
CERT_SUBJECT="/C=US/ST=CA/L=Sunnyvale/O=Tunnel Service./CN=Tunnel Service"

[ ! -d $OUTPUT_FOLDER ] && mkdir $OUTPUT_FOLDER
[ ! -d $CERT_FOLDER ] && mkdir $CERT_FOLDER

if [ ! -f $CERT_FOLDER/ca.crt ]; then
    openssl genrsa -out $CERT_FOLDER/ca.key 2048
    openssl req -new -x509 -days 3650 -key $CERT_FOLDER/ca.key -subj "$CA_SUBJECT" -out $CERT_FOLDER/ca.crt
else
    echo Skiping CA generation.
fi

if [ ! -f $CERT_FOLDER/cert.crt ]; then
    echo Generating $CERT_FOLDER/cert.key...
    openssl req -newkey rsa:2048 -nodes -keyout $CERT_FOLDER/cert.key -subj "$CERT_SUBJECT tunnel" -out $CERT_FOLDER/cert.csr
    openssl x509 -req -extfile <(printf "subjectAltName=DNS:tunnel") -days 3650 -in $CERT_FOLDER/cert.csr -CA $CERT_FOLDER/ca.crt -CAkey $CERT_FOLDER/ca.key -CAcreateserial -out $CERT_FOLDER/cert.crt
    echo tunnel > $CERT_FOLDER/servername.txt
else
    echo Skiping $CERT_FOLDER/cert.key
fi

for ARCH in arm arm64 amd64; do
    OUTPUT_FULLNAME=$OUTPUT_FOLDER/clover3-tunnel.${ARCH}
    CGO_ENABLED=0 GOOS=linux GOARCH=$ARCH go build -ldflags "-s -w" -o $OUTPUT_FULLNAME $SRC_FOLDER
    upx $OUTPUT_FULLNAME
done

GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o $OUTPUT_FOLDER/clover3-tunnel.exe $SRC_FOLDER
