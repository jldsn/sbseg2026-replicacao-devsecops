"""Confirmação dirigida da P4 em uma instância descartável do Juice Shop em loopback.

Caso coberto: métricas expostas sem autenticação (js-exposed-metrics). O oráculo
independente é o placar oficial de desafios da própria aplicação (/api/Challenges),
além da resposta HTTP. O teste é somente leitura (GET), sem efeito colateral na
aplicação.

O caso js-rce-b2b (execução de código no endpoint /b2b/v2/orders) NÃO é testado por
este script. Confirmar esse caso exigiria enviar ao servidor um payload desenhado para
produzir um laço de repetição não controlado dentro do avaliador do endpoint — mesmo
sendo o próprio teste oficial documentado pelos mantenedores do Juice Shop para esse
desafio, trata-se de uma ação com efeito de negação de serviço sobre o processo-alvo.
Por prudência, o grupo optou por não automatizar esse teste e registra o caso como
`nao_executada`, apoiado apenas na evidência estática (Semgrep sobre o uso de `vm` com
entrada controlada pelo cliente) e na evidência indireta do Trivy. Ver docs/protocolo.md.

Os dois casos de XSS (js-dom-xss, js-reflected-xss) exigem um navegador real e ficam
para verificação manual, documentada em docs/pilotos.md.
"""

import argparse
import json
import re
import urllib.error
import urllib.request
from pathlib import Path


def http(base, rota):
    req = urllib.request.Request(base + rota, method="GET")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        resp = opener.open(req, timeout=20)
    except urllib.error.HTTPError as err:
        resp = err
    with resp:
        return resp.code, resp.read().decode("utf-8", "replace")


def desafio_resolvido(base, chave):
    _, corpo = http(base, f"/api/Challenges/?key={chave}")
    dados = json.loads(corpo).get("data") or [{}]
    return bool(dados[0].get("solved"))


def metricas(base):
    antes = desafio_resolvido(base, "exposedMetricsChallenge")
    code, corpo = http(base, "/metrics")
    formato = bool(re.search(r"^# HELP \w+", corpo, re.M))
    depois = desafio_resolvido(base, "exposedMetricsChallenge")
    confirmada = code == 200 and formato and depois
    return {"status": "confirmada" if confirmada else "inconclusiva", "rota": "/metrics",
            "metodo": "GET", "autenticacao": "nenhuma", "http": code,
            "formato_prometheus": formato,
            "series_expostas": len(re.findall(r"^# HELP ", corpo, re.M)),
            "desafio_oficial": "exposedMetricsChallenge",
            "resolvido_antes": antes, "resolvido_depois": depois}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="http://127.0.0.1:PORTA da instância descartável")
    parser.add_argument("--configuracao", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    base = args.base.rstrip("/")
    if not re.fullmatch(r"http://127\.0\.0\.1:\d+", base):
        parser.error("Use uma instância HTTP descartável vinculada a 127.0.0.1.")
    _, versao = http(base, "/rest/admin/application-version")
    laudo = {"configuracao": args.configuracao, "base": base, "versao": json.loads(versao),
             "casos": {"js-exposed-metrics": metricas(base)}}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(laudo, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    for vid, caso in laudo["casos"].items():
        print(f"{vid}: {caso['status']}")


if __name__ == "__main__":
    main()
