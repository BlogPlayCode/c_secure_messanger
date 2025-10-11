#!/bin/bash

./compile.sh
if [ -f "utility_cli.out" ]; then
    ./utility_cli.out
elif [ -f "utility_cli.exe" ]; then
    ./utility_cli.exe
else
    echo "Build may have failed - no output file found"
fi
