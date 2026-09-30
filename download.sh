#!/usr/bin/env bash
#
# download.sh : download the Temurin OpenJDK MSI and the Ghidra release zip
#               used by the installer and verify their SHA-256 checksums

set -euo pipefail

JDK_VERSION="17"
JDK_API="https://api.adoptium.net/v3/assets/latest/${JDK_VERSION}/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse"
GHIDRA_API="https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest"

# downloads go next to this script, where GhidraLaunchSetup/Bundle.wxs expects them
cd "$(dirname "${BASH_SOURCE[0]}")"

# print the lowercase SHA-256 of a file
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi | cut -d ' ' -f 1 | tr '[:upper:]' '[:lower:]'
}

# download <name> <url> <sha256> <output>
download() {
  local name="$1" url="$2" checksum="$3" output="$4"

  checksum="$(tr '[:upper:]' '[:lower:]' <<<"${checksum}")"
  echo -n "${name}"

  if [[ -z "${url}" || ! "${checksum}" =~ ^[0-9a-f]{64}$ ]]; then
    echo "  [❌] release URL or checksum not found"
    return 1
  fi

  if ! curl --silent --show-error --fail --location --output "${output}.part" "${url}"; then
    rm -f "${output}.part"
    echo "  [❌] download failed"
    return 1
  fi

  if [[ "$(sha256 "${output}.part")" != "${checksum}" ]]; then
    rm -f "${output}.part"
    echo "  [❌] checksum mismatch"
    return 1
  fi

  mv -f "${output}.part" "${output}"
  echo "  [✔️]"
}

status=0

# Temurin OpenJDK MSI, checksum published by Adoptium
jdk_json="$(curl --silent --show-error --fail "${JDK_API}")" || jdk_json="[]"
download "Latest Temurin OpenJDK ${JDK_VERSION}" \
  "$(jq -r '.[0].binary.installer.link // empty' <<<"${jdk_json}")" \
  "$(jq -r '.[0].binary.installer.checksum // empty' <<<"${jdk_json}")" \
  "OpenJDK${JDK_VERSION}U-jdk_x64.msi" || status=1

# Ghidra release zip, checksum published in the release notes
ghidra_json="$(curl --silent --show-error --fail --header "Accept: application/vnd.github+json" "${GHIDRA_API}")" || ghidra_json="{}"
download "Latest Ghidra" \
  "$(jq -r '[.assets[]? | select(.name | test("^ghidra_.*_PUBLIC_[0-9]+\\.zip$"))][0].browser_download_url // empty' <<<"${ghidra_json}")" \
  "$(jq -r '.body // empty' <<<"${ghidra_json}" | grep -oiE 'SHA-256:[^0-9a-f]*[0-9a-f]{64}' | grep -oiE '[0-9a-f]{64}' | head -n 1 || true)" \
  "Ghidra.zip" || status=1

exit "${status}"
