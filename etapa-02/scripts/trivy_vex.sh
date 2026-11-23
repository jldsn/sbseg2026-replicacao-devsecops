#!/bin/bash
# Critério S4 da P4 (docs/p4-acoes.md): roda o Trivy oficial com e sem o VEX gerado por
# scripts/politica_acoes.py, numa imagem do TeaStore e na do Juice Shop.
# Saída bruta (grande) fica fora do repositório, em ~/.cache/trivy-p4/out; o resumo versionado
# sai de scripts/validar_vex_trivy.py. Requer Docker; imagens já baixadas localmente.
# O diretório de trabalho fica na home porque o colima só compartilha a home com a VM.
set -euo pipefail
ETAPA="$(cd "$(dirname "$0")/.." && pwd)"
W="$HOME/.cache/trivy-p4"; mkdir -p "$W/cache" "$W/out" "$W/vex"
cp "$ETAPA"/pilotos/contexto-acoes/vex-*.json "$W/vex/"
T="aquasec/trivy@sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c"  # 0.69.3
run() {
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$W/cache:/root/.cache" \
    -v "$W/out:/out" -v "$W/vex:/vex:ro" "$T" image --quiet --scanners vuln --format json "$@"
}
WEBUI=descartesresearch/teastore-webui:1.4.2
JUICE=bkimminich/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58
run -o /out/webui-sem.json "$WEBUI"
run --skip-db-update --skip-java-db-update --show-suppressed --vex /vex/vex-teastore--image-webui.json \
  -o /out/webui-com.json "$WEBUI"
run --skip-db-update --skip-java-db-update -o /out/juice-sem.json "$JUICE"
run --skip-db-update --skip-java-db-update --show-suppressed --vex /vex/vex-juice-shop--juice-shop-image.json \
  -o /out/juice-com.json "$JUICE"
