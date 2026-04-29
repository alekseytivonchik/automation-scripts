#!/usr/bin/env bash
set -euo pipefail

USER_NAME="${1:-developer}"
GROUP_NAME="${2:-developers}"
CLUSTER_NAME="${3:-$(kubectl config view --minify -o jsonpath='{.clusters[0].name}' 2>/dev/null || echo kubernetes)}"
NAMESPACE="${4:-default}"
DAYS="${DAYS:-3650}"

CA_CRT="${CA_CRT:-/etc/kubernetes/pki/ca.crt}"
CA_KEY="${CA_KEY:-/etc/kubernetes/pki/ca.key}"
OUT_DIR="${OUT_DIR:-./kube-user-${USER_NAME}}"

mkdir -p "${OUT_DIR}"
chmod 700 "${OUT_DIR}"

SERVER="$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')"
CONTEXT_NAME="${USER_NAME}@${CLUSTER_NAME}"

echo "[INFO] User: ${USER_NAME}"
echo "[INFO] Group: ${GROUP_NAME}"
echo "[INFO] Cluster: ${CLUSTER_NAME}"
echo "[INFO] Server: ${SERVER}"
echo "[INFO] Namespace: ${NAMESPACE}"
echo "[INFO] Validity: ${DAYS} days"
echo "[INFO] Output dir: ${OUT_DIR}"

if [[ ! -f "${CA_CRT}" ]]; then
  echo "[ERROR] CA certificate not found: ${CA_CRT}"
  exit 1
fi

if [[ ! -f "${CA_KEY}" ]]; then
  echo "[ERROR] CA key not found: ${CA_KEY}"
  exit 1
fi

if [[ -z "${SERVER}" ]]; then
  echo "[ERROR] Cannot detect Kubernetes API server from current kubeconfig"
  exit 1
fi

KEY_FILE="${OUT_DIR}/${USER_NAME}.key"
CSR_FILE="${OUT_DIR}/${USER_NAME}.csr"
CRT_FILE="${OUT_DIR}/${USER_NAME}.crt"
KUBECONFIG_FILE="${OUT_DIR}/${USER_NAME}.kubeconfig"

echo "[INFO] Generating private key..."
openssl genrsa -out "${KEY_FILE}" 4096

echo "[INFO] Generating CSR..."
openssl req -new \
  -key "${KEY_FILE}" \
  -out "${CSR_FILE}" \
  -subj "/CN=${USER_NAME}/O=${GROUP_NAME}"

echo "[INFO] Signing certificate with cluster CA..."
openssl x509 -req \
  -in "${CSR_FILE}" \
  -CA "${CA_CRT}" \
  -CAkey "${CA_KEY}" \
  -CAcreateserial \
  -out "${CRT_FILE}" \
  -days "${DAYS}" \
  -sha256

echo "[INFO] Creating kubeconfig with embedded certificates..."
kubectl config --kubeconfig="${KUBECONFIG_FILE}" set-cluster "${CLUSTER_NAME}" \
  --server="${SERVER}" \
  --certificate-authority="${CA_CRT}" \
  --embed-certs=true >/dev/null

kubectl config --kubeconfig="${KUBECONFIG_FILE}" set-credentials "${USER_NAME}" \
  --client-certificate="${CRT_FILE}" \
  --client-key="${KEY_FILE}" \
  --embed-certs=true >/dev/null

kubectl config --kubeconfig="${KUBECONFIG_FILE}" set-context "${CONTEXT_NAME}" \
  --cluster="${CLUSTER_NAME}" \
  --user="${USER_NAME}" \
  --namespace="${NAMESPACE}" >/dev/null

kubectl config --kubeconfig="${KUBECONFIG_FILE}" use-context "${CONTEXT_NAME}" >/dev/null

chmod 600 "${KUBECONFIG_FILE}"

echo "[INFO] Certificate info:"
openssl x509 -in "${CRT_FILE}" -noout -subject -issuer -dates

echo
echo "[DONE] Kubeconfig created:"
echo "${KUBECONFIG_FILE}"
echo
echo "Check:"
echo "KUBECONFIG=${KUBECONFIG_FILE} kubectl auth whoami"
echo "KUBECONFIG=${KUBECONFIG_FILE} kubectl get pods -n ${NAMESPACE}"
echo
echo "Important:"
echo "RBAC is not created by this script."
echo "Give developer only this file:"
echo "${KUBECONFIG_FILE}"
