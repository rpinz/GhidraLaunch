#!/usr/bin/env bash

echo -n "Latest Temurin OpenJDK"
curl --silent --location --output "OpenJDK17U-jdk_x64.msi" \
  $(curl --silent "https://api.github.com/repos/adoptium/temurin17-binaries/releases" | jq -r '.[0].assets[137].browser_download_url') \
  && echo "  [✔️]" \
  || echo "  [❌]"

echo -n "Latest Ghidra"
curl --silent --location --output "Ghidra.zip" \
  $(curl --silent "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases" | jq -r '.[0].assets[0].browser_download_url') \
  && echo "  [✔️]" \
  || echo "  [❌]"

