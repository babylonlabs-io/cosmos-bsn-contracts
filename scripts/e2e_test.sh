#!/bin/bash

set -e  # Exit immediately if any command fails

cd e2e
make test
cd -
