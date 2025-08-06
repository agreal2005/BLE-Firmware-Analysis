# Use Ubuntu base image
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install tools and OpenJDK 17 FULL (not headless)
RUN apt-get update && \
    apt-get install -y \
      wget unzip openjdk-17-jdk python3 python3-pip git \
      build-essential cmake ninja-build libboost-all-dev libssl-dev \
      libprotobuf-dev protobuf-compiler

# Install Ghidra (v10.4 as recommended in your README)
WORKDIR /opt
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip -O ghidra.zip && \
    unzip ghidra.zip && rm ghidra.zip

ENV GHIDRA_DIR=/opt/ghidra_10.4_PUBLIC
ENV PATH=${GHIDRA_DIR}/support:${PATH}

# Install BinDiff 8 on Linux (Debian package only)
WORKDIR /tmp
RUN wget https://github.com/google/bindiff/releases/download/v8/bindiff_8_amd64.deb && \
    apt-get update && \
    apt-get install -y ./bindiff_8_amd64.deb && \
    rm -f bindiff_8_amd64.deb


# Copy requirements.txt and install only needed pip packages
COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

# Copy the rest of your project files
COPY . /workspace
WORKDIR /workspace

# Make your run.sh scripts executable
RUN chmod +x /workspace/ti/run.sh || true
RUN chmod +x /workspace/nordic/run.sh || true

# Default is a bash shell (customize entrypoint if needed)
CMD ["/bin/bash"]

