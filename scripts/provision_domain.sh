#!/usr/bin/env bash
set -e
DOMAIN=$1
DEPTH=${2:-1}
curl -X POST "http://localhost:8080/provision/domain/$DOMAIN?depth=$DEPTH"
