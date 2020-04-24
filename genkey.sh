#!/bin/bash

mkdir -p .key && cd .key

echo "generate CA key and certificate"

openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key \
    -subj "/C=TW/ST=Taiwan/L=Taipei City/O=MyOrg/OU=MyUnit/CN=my.ca" \
    -sha256 -days 365 -out ca.crt
echo "CA key is ca.key"
echo "CA cert is ca.crt"

printf "\ngenerate server key and certificate\n"
openssl genrsa -out host.key 4096
openssl req -new -key host.key -subj "/C=TW/ST=Taiwan/L=Taipei City/O=MyOrg/OU=MyUnit/CN=my.domain" -sha256 -out host.csr
openssl x509 -req -in host.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out host.crt -days 30 -sha256
echo "server key is host.key"
echo "server cert is host.crt"

printf "\ngenerate client key and certificate\n"
openssl genrsa -out client.key 4096
openssl req -new -key client.key -subj "/C=TW/ST=Taiwan/L=Taipei City/O=MyOrg/OU=MyUnit/CN=my.client" -sha256 -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 30 -sha256
echo "client key is client.key"
echo "client cert is client.crt"