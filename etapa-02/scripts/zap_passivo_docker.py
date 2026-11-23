"""Coleta ZAP somente passiva (spider + regras passivas) contra um alvo em Docker.

Mesmos passos e mesma saída da parte passiva de `piloto_dast.py` (Juice Shop), mas com o
ZAP e o alvo em contêineres da mesma rede, para rodar em macOS (sem `unshare`). Não
executa escaneamento ativo: nenhuma regra de ataque do ZAP é disparada.
"""

import argparse
import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
API_KEY = "piloto-loopback"


def zap_api(zap, endpoint, **params):
    query = urllib.parse.urlencode({"apikey": API_KEY, **params})
    with HTTP.open(f"{zap}/JSON/{endpoint}/?{query}", timeout=30) as r:
        return json.loads(r.read())


def aguardar(funcao, descricao, limite):
    prazo = time.monotonic() + limite
    while time.monotonic() < prazo:
        try:
            if funcao():
                return
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            pass
        time.sleep(2)
    raise TimeoutError(descricao)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("app")
    p.add_argument("--alvo", required=True, help="URL inicial vista de dentro da rede Docker")
    p.add_argument("--base", required=True, help="Prefixo das URLs a exportar")
    p.add_argument("--zap", default="http://127.0.0.1:18090")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--spider-min", default="2")
    a = p.parse_args()
    a.out.mkdir(parents=True, exist_ok=True)
    aguardar(lambda: zap_api(a.zap, "core/view/version"), "ZAP", 180)
    versao = zap_api(a.zap, "core/view/version")
    zap_api(a.zap, "core/action/accessUrl", url=a.alvo, followRedirects="true")
    zap_api(a.zap, "spider/action/setOptionMaxDuration", Integer=a.spider_min)
    sid = zap_api(a.zap, "spider/action/scan", url=a.alvo, recurse="true")["scan"]
    aguardar(lambda: zap_api(a.zap, "spider/view/status", scanId=sid)["status"] == "100",
             "Spider", 60 * int(a.spider_min) + 60)
    aguardar(lambda: zap_api(a.zap, "pscan/view/recordsToScan")["recordsToScan"] == "0",
             "Fila passiva", 300)
    urls = zap_api(a.zap, "core/view/urls", baseurl=a.base)["urls"]
    alertas = zap_api(a.zap, "core/view/alerts", baseurl=a.base, start=0, count=10000)["alerts"]
    passivo = a.out / f"{a.app}-passivo.json"
    passivo.write_text(json.dumps({"urls": urls, "alerts": alertas}, ensure_ascii=False,
                                  indent=2) + "\n", encoding="utf-8")
    resumo = {"app": a.app, "healthcheck": a.alvo, "autenticado": False,
              "rede": "docker_bridge_portas_em_127.0.0.1", "zap": versao,
              "escaneamento_ativo": "nao_executado", "spider_max_min": int(a.spider_min),
              "urls_passivas": len(urls), "alertas_passivos": len(alertas),
              "sha256_passivo": hashlib.sha256(passivo.read_bytes()).hexdigest()}
    (a.out / f"{a.app}-resumo.json").write_text(json.dumps(resumo, ensure_ascii=False,
                                                indent=2) + "\n", encoding="utf-8")
    print(json.dumps(resumo, indent=2))


if __name__ == "__main__":
    main()
