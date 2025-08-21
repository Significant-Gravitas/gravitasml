#!/bin/bash -eu
# Copyright 2024 GravitasML Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

# Install the project with current CFLAGS, CXXFLAGS
pip3 install --prefer-binary .

# Install fuzzing dependencies
pip3 install hypothesis

# Build fuzzers in $OUT
for fuzzer in $(find $SRC -name '*_fuzzer.py'); do
  compile_python_fuzzer $fuzzer
done