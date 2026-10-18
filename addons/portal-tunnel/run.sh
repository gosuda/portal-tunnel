#!/bin/sh
set -eu

OPTIONS_FILE="${PORTAL_ADDON_OPTIONS:-/data/options.json}"
DATA_DIR="${PORTAL_ADDON_DATA_DIR:-/data}"
CONFIG_FILE="${DATA_DIR}/config.toml"
IDENTITY_FILE="${DATA_DIR}/identity.json"

if [ ! -f "${OPTIONS_FILE}" ]; then
  echo "error: ${OPTIONS_FILE} not found" >&2
  exit 1
fi

AUTH="$(jq -r '.auth // empty' "${OPTIONS_FILE}" | tr '[:upper:]' '[:lower:]')"
case "${AUTH}" in
  credential|oidc|siwe) ;;
  *)
    echo "error: unauthenticated exposure is refused; set auth to credential, oidc, or siwe" >&2
    exit 1
    ;;
esac

ALLOWED_COUNT="$(jq -r '(.auth_allowed_principals // []) | map(select(length > 0)) | length' "${OPTIONS_FILE}")"
if [ "${ALLOWED_COUNT}" -le 0 ]; then
  echo "error: auth_allowed_principals must contain at least one allowed principal" >&2
  exit 1
fi

if [ "${AUTH}" = "oidc" ]; then
  OIDC_ISSUER="$(jq -r '.auth_oidc_issuer // empty' "${OPTIONS_FILE}")"
  OIDC_CLIENT_ID="$(jq -r '.auth_oidc_client_id // empty' "${OPTIONS_FILE}")"
  if [ -z "${OIDC_ISSUER}" ] || [ -z "${OIDC_CLIENT_ID}" ]; then
    echo "error: auth=oidc requires auth_oidc_issuer and auth_oidc_client_id" >&2
    exit 1
  fi
fi

mkdir -p "${DATA_DIR}"
umask 077

jq -r --arg state_dir "${DATA_DIR}" --arg identity_path "${IDENTITY_FILE}" '
  "[agent]
" +
  "state_dir = " + ($state_dir | @json) + "
" +
  "control_addr = \"127.0.0.1:4018\"

" +
  "[[tunnels]]
" +
  "id = \"default\"
" +
  "name = " + ((.name // "my-home") | @json) + "
" +
  "target = " + ((.target // "127.0.0.1:8123") | @json) + "
" +
  "identity_path = " + ($identity_path | @json) + "
" +
  "discovery = " + ((if .discovery == null then true else .discovery end) | tostring) + "
" +
  "overlay = " + ((.overlay // false) | tostring) + "
" +
  "ban_mitm = " + ((.ban_mitm // false) | tostring) + "
" +
  "auth = " + (.auth | @json) + "
" +
  "auth_allowed_wallets = " + ((.auth_allowed_principals // []) | @json) + "
" +
  "auth_identity_headers = " + ((.auth_identity_headers // false) | tostring) + "
" +
  (if (.relays // [] | length) > 0 then "relays = " + (.relays | @json) + "
" else "" end) +
  (if (.auth_oidc_issuer // "") != "" then "auth_oidc_issuer = " + (.auth_oidc_issuer | @json) + "
" else "" end) +
  (if (.auth_oidc_client_id // "") != "" then "auth_oidc_client_id = " + (.auth_oidc_client_id | @json) + "
" else "" end) +
  (if (.auth_oidc_client_secret // "") != "" then "auth_oidc_client_secret = " + (.auth_oidc_client_secret | @json) + "
" else "" end)
' "${OPTIONS_FILE}" > "${CONFIG_FILE}"

chmod 600 "${CONFIG_FILE}"

exec /usr/bin/portal agent run --config "${CONFIG_FILE}" --foreground
