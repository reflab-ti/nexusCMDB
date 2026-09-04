#!/bin/sh
set -eu

DOMAIN="${CERTBOT_DOMAIN:-dev-nexuscmdb.reflab.dev}"
EMAIL="${CERTBOT_EMAIL:?Define CERTBOT_EMAIL en .env para registrar el certificado Let's Encrypt.}"
RENEW_BEFORE_DAYS="${CERTBOT_RENEW_BEFORE_DAYS:-30}"
PROPAGATION_SECONDS="${CERTBOT_DNS_PROPAGATION_SECONDS:-60}"
CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
GENERATED_CREDENTIALS_PATH="/tmp/cloudflare.ini"
FALLBACK_CREDENTIALS_PATH="/etc/letsencrypt/dns-credentials.ini"

echo "=== [$(date)] Verificacion semanal de certificado Let's Encrypt DNS-01 para ${DOMAIN} ==="

build_cloudflare_credentials() {
  if [ -n "${CLOUDFLARE_API_TOKEN:-}" ]; then
    umask 077
    printf 'dns_cloudflare_api_token = %s\n' "${CLOUDFLARE_API_TOKEN}" > "${GENERATED_CREDENTIALS_PATH}"
    echo "${GENERATED_CREDENTIALS_PATH}"
    return
  fi

  if [ -f "${FALLBACK_CREDENTIALS_PATH}" ]; then
    echo "${FALLBACK_CREDENTIALS_PATH}"
    return
  fi

  echo "ERROR: define CLOUDFLARE_API_TOKEN en .env o monta ${FALLBACK_CREDENTIALS_PATH}." >&2
  exit 1
}

request_certificate() {
  CREDENTIALS_PATH="$(build_cloudflare_credentials)"
  STAGING_ARGS=""
  if [ "${CERTBOT_STAGING:-0}" = "1" ]; then
    STAGING_ARGS="--staging"
  fi

  echo "Solicitando/renovando certificado para ${DOMAIN} mediante Cloudflare DNS-01..."
  certbot certonly \
    --non-interactive \
    --agree-tos \
    --keep-until-expiring \
    --email "${EMAIL}" \
    --dns-cloudflare \
    --dns-cloudflare-credentials "${CREDENTIALS_PATH}" \
    --dns-cloudflare-propagation-seconds "${PROPAGATION_SECONDS}" \
    ${STAGING_ARGS} \
    -d "${DOMAIN}"
}

if [ ! -f "${CERT_PATH}" ] || [ ! -f "${KEY_PATH}" ]; then
  echo "No existe certificado completo para ${DOMAIN}. Se solicitara uno nuevo."
  request_certificate
  echo "=== Fin del proceso de verificacion ==="
  exit 0
fi

EXP_DATE="$(openssl x509 -enddate -noout -in "${CERT_PATH}" | cut -d= -f2)"
RENEW_BEFORE_SECONDS="$((RENEW_BEFORE_DAYS * 86400))"

echo "El certificado para ${DOMAIN} caduca el: ${EXP_DATE}"

if ! openssl x509 -checkend "${RENEW_BEFORE_SECONDS}" -noout -in "${CERT_PATH}" >/dev/null; then
  echo "El certificado esta dentro del umbral de renovacion (${RENEW_BEFORE_DAYS} dias)."
  request_certificate
else
  echo "El certificado conserva mas de ${RENEW_BEFORE_DAYS} dias de vigencia. No se requiere renovacion."
fi

echo "=== Fin del proceso de verificacion ==="
