#!/bin/sh
set -eu

DOMAIN="${CERTBOT_DOMAIN:-dev-nexuscmdb.reflab.dev}"
APP_PORT="${APP_PORT:-3002}"
CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
KEY_PATH="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
TEMPLATE_PATH="/etc/nginx/nginx.conf.template"

echo "Esperando certificado TLS para ${DOMAIN}..."
until [ -f "${CERT_PATH}" ] && [ -f "${KEY_PATH}" ]; do
  echo "Certificado no disponible todavia en ${CERT_PATH}. Reintentando en 30 segundos..."
  sleep 30
done

sed \
  -e "s#__CERTBOT_DOMAIN__#${DOMAIN}#g" \
  -e "s#__APP_PORT__#${APP_PORT}#g" \
  "${TEMPLATE_PATH}" > /etc/nginx/nginx.conf

(
  while :; do
    sleep "${NGINX_CERT_RELOAD_INTERVAL:-12h}"
    nginx -s reload || true
  done
) &

exec nginx -g 'daemon off;'
