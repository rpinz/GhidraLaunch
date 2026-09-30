#!/usr/bin/env bash
#
# download.sh : download the Temurin OpenJDK MSI and the Ghidra release zip
#               used by the installer and verify their SHA-256 checksums

set -euo pipefail

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
ghidra_downloaded=0
java_version=""
versions_file="GhidraLaunchSetup/Versions.wxi"
rm -f "${versions_file}"

# Ghidra release zip, checksum published in the release notes
ghidra_json="$(curl --silent --show-error --fail --header "Accept: application/vnd.github+json" "${GHIDRA_API}")" || ghidra_json="{}"
ghidra_asset="$(jq -c '[.assets[]? | select(.name | test("^ghidra_.*_PUBLIC_[0-9]+\\.zip$"))][0] // {}' <<<"${ghidra_json}")"
ghidra_checksum="$(jq -r --argjson asset "${ghidra_asset}" '
  def hashes: [match("SHA-256:[^0-9a-f]*([0-9a-f]{64})(?![0-9a-f])"; "ig") | .captures[0].string];
  if ($asset.digest // "") != "" then
    if ($asset.digest | test("^sha256:[0-9a-f]{64}$"; "i")) then $asset.digest[7:] else empty end
  else
    (.body // "") as $body
    | ($body | hashes) as $all
    | ($asset.name // "" | gsub("[.]"; "[.]")) as $name
    | ($body | split("\n")) as $lines
    | "([A-Za-z0-9_.-]+[.](zip|msi|exe|tar|gz|7z))(?=[^A-Za-z0-9_.-]|$)" as $filePattern
    | ([range(0; $lines | length) as $i
        | $lines[$i]
        | select(test("(^|[^A-Za-z0-9_.-])" + $name + "($|[^A-Za-z0-9_.-])"))
        | select(([match($filePattern; "ig") | .captures[0].string] | unique) == [$asset.name])
        | if (hashes | length) > 0 then hashes[]
          elif ($i + 1 < ($lines | length)) and ($lines[$i + 1] | test($filePattern; "i") | not)
          then ($lines[$i + 1] | hashes[])
          else empty end]) as $named
    | if ($named | length) == 1 then $named[0]
      elif ($named | length) == 0 and ($all | length) == 1
        and ([$lines[] | select(hashes | length > 0)
              | select(test($filePattern; "i") | not)] | length) == 1
      then $all[0]
      else empty end
  end
' <<<"${ghidra_json}")"
if download "Latest Ghidra" \
  "$(jq -r '.browser_download_url // empty' <<<"${ghidra_asset}")" \
  "${ghidra_checksum}" \
  "Ghidra.zip"; then
  ghidra_downloaded=1
else
  status=1
fi

if [[ "${ghidra_downloaded}" -eq 1 ]]; then
  application_properties="$(unzip -Z1 Ghidra.zip | awk '/(^|\/)Ghidra\/application\.properties$/ { print; exit }')" || application_properties=""
  if [[ -z "${application_properties}" ]]; then
    echo "Ghidra Java requirement not found in release archive"
    status=1
  else
    java_version="$(unzip -p Ghidra.zip "${application_properties}" | awk -F= '$1 == "application.java.min" { gsub(/[[:space:]]/, "", $2); print $2; exit }')" || java_version=""
    if [[ ! "${java_version}" =~ ^[0-9]+$ ]]; then
      echo "Ghidra Java requirement is missing or invalid"
      status=1
    else
      # Temurin OpenJDK MSI, checksum published by Adoptium
      jdk_api="https://api.adoptium.net/v3/assets/latest/${java_version}/hotspot?architecture=x64&image_type=jdk&os=windows&vendor=eclipse"
      jdk_json="$(curl --silent --show-error --fail "${jdk_api}")" || jdk_json="[]"
      download "Latest Temurin OpenJDK ${java_version}" \
        "$(jq -r '.[0].binary.installer.link // empty' <<<"${jdk_json}")" \
        "$(jq -r '.[0].binary.installer.checksum // empty' <<<"${jdk_json}")" \
        "OpenJDK${java_version}U-jdk_x64.msi" || status=1
    fi
  fi
fi

if [[ "${status}" -eq 0 ]]; then
  printf '<?define JavaVersion = "%s" ?>\n' "${java_version}" > "${versions_file}"
fi

exit "${status}"
