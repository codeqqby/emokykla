#!/bin/bash

curl -H 'Content-Type: application/json' -d @- "http://127.0.0.1:6544/login" <<EOF
{
	"uid": "$1",
	"password": "$2"
}
EOF

echo
