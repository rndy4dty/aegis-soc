#!/usr/bin/env bash
set -euo pipefail

RELEASE_NAME="${RELEASE_NAME:-aegis-soc}"
NAMESPACE="${NAMESPACE:-aegis-soc}"
CHART_DIR="$(cd "$(dirname "$0")/helm/aegis-soc" && pwd)"

cmd_build() {
    echo "Building images..."
    docker build -t aegis-soc-api:latest -f deploy/Dockerfile.api .
    docker build -t aegis-soc-dashboard:latest -f deploy/Dockerfile.dashboard .
    echo "Done."
}

cmd_install() {
    echo "Installing ${RELEASE_NAME} into ${NAMESPACE}..."
    kubectl create namespace "${NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
    helm install "${RELEASE_NAME}" "${CHART_DIR}" \
        --namespace "${NAMESPACE}" \
        --wait
}

cmd_upgrade() {
    helm upgrade "${RELEASE_NAME}" "${CHART_DIR}" \
        --namespace "${NAMESPACE}" \
        --wait
}

cmd_uninstall() {
    helm uninstall "${RELEASE_NAME}" --namespace "${NAMESPACE}" || true
    kubectl delete namespace "${NAMESPACE}" --ignore-not-found
}

cmd_template() {
    helm template "${RELEASE_NAME}" "${CHART_DIR}" \
        --namespace "${NAMESPACE}"
}

case "${1:-}" in
    build)      cmd_build ;;
    install)    cmd_install ;;
    upgrade)    cmd_upgrade ;;
    uninstall)  cmd_uninstall ;;
    template)   cmd_template ;;
    *)
        echo "Usage: $0 {build|install|upgrade|uninstall|template}"
        exit 1
        ;;
esac
