FROM gcr.io/oss-fuzz-base/base-builder-python

# Install Python dependencies needed for fuzzing
RUN pip3 install hypothesis atheris

# Clone the project repository
RUN git clone \
    --depth 1 \
    --branch main \
    https://github.com/Significant-Gravitas/gravitasml.git

WORKDIR gravitasml

# Copy fuzzing scripts and build script
COPY build.sh tokenizer_fuzzer.py parser_fuzzer.py hypothesis_structured_fuzzer.py $SRC/