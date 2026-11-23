"""Catálogo de testes benignos da P4: confirmação automática escolhida pelo CWE do caso.

Protocolo em docs/p4-avaliacao.md, seção 7. Nenhum modelo envia payload de ataque: só
requisições que a própria aplicação oferece (um GET numa rota, o envio de um formulário
público com os valores padrão). Cada modelo roda também um controle negativo, que precisa
reprovar. Só aceita alvos em 127.0.0.1.

XSS e `js-rce-b2b` ficam fora por decisão de protocolo; verificações de configuração
estática não contam como confirmação. A DVWA reaproveita o laudo de validar_dvwa_http.py,
que já é o teste automatizado desses casos.
"""

import argparse
import csv
import hashlib
import json
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ETAPA = Path(__file__).resolve().parent.parent


class SemRedirecionamento(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}), SemRedirecionamento())


def requisitar(url, dados=None):
    """Requisição sem cookies e sem seguir redirecionamento; devolve o registro bruto."""
    corpo = urllib.parse.urlencode(dados).encode() if dados else None
    req = urllib.request.Request(url, data=corpo)
    try:
        resp = HTTP.open(req, timeout=60)
    except urllib.error.HTTPError as err:
        resp = err
    texto = resp.read().decode("utf-8", "replace")
    return {"metodo": "POST" if corpo else "GET", "url": url,
            "corpo_enviado": corpo.decode() if corpo else None, "cookies_enviados": None,
            "http": resp.status, "location": resp.headers.get("Location"),
            "content_type": resp.headers.get("Content-Type"),
            "sha256_corpo": hashlib.sha256(texto.encode()).hexdigest(),
            "inicio_do_corpo": texto[:300]}, texto


def loga_desde(container, desde, padrao):
    saida = subprocess.run(["docker", "logs", "--since", desde, container],
                           capture_output=True, text=True, check=True)
    linhas = (saida.stdout + saida.stderr).splitlines()
    return [linha for linha in linhas if padrao in linha]


# --- Modelos -----------------------------------------------------------------------------

def acesso_sem_autenticacao(base, rota, marcador, controle):
    """CWE-306/284/200: a função sensível responde sem sessão; a rota de controle não."""
    reg, texto = requisitar(base + rota)
    ok = reg["http"] == 200 and re.search(marcador, texto, re.M) is not None
    ctrl, _ = requisitar(base + controle)
    controle_reprovou = ctrl["http"] in (301, 302, 303, 401, 403)
    return {"modelo": "acesso_sem_autenticacao",
            "criterio": f"HTTP 200 e conteúdo /{marcador}/ sem sessão",
            "requisicao": reg, "criterio_atendido": ok,
            "controle_negativo": {"requisicao": ctrl, "reprovou": controle_reprovou},
            "status": "confirmada" if ok and controle_reprovou else "inconclusiva"}


def funcao_critica_sem_autenticacao(base, rota, formulario, sucesso, container, log):
    """CWE-306: a ação executa sem sessão (efeito no log); sem confirmação, não executa."""
    inicio = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ctrl, _ = requisitar(base + rota)  # controle: sem o parâmetro de confirmação
    time.sleep(3)
    efeito_controle = loga_desde(container, inicio, log)
    controle_reprovou = ctrl["location"] != sucesso and not efeito_controle
    inicio = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    reg, _ = requisitar(base + rota, formulario)
    time.sleep(3)
    efeito = loga_desde(container, inicio, log)
    ok = reg["http"] in (302, 303) and (reg["location"] or "").endswith(sucesso) and bool(efeito)
    return {"modelo": "funcao_critica_sem_autenticacao",
            "criterio": f"redireciona para {sucesso} e o serviço registra '{log}', sem sessão",
            "requisicao": reg, "log_do_servico": efeito, "criterio_atendido": ok,
            "controle_negativo": {"requisicao": ctrl, "log_do_servico": efeito_controle,
                                  "reprovou": controle_reprovou},
            "status": "confirmada" if ok and controle_reprovou else "inconclusiva"}


# --- Casos da fila -----------------------------------------------------------------------
# categoria: dinamico (tem modelo benigno), configuracao (só verificação estática, não
# confirma), sem_modelo (XSS: exige payload no navegador), excluido (efeito de DoS).

FILA = {
    "dvwa": {
        "dvwa-csrf": ("dinamico", "csrf", "laudo de validar_dvwa_http.py"),
        "dvwa-weak-session-ids": ("dinamico", "ids_previsiveis", "laudo de validar_dvwa_http.py"),
        "dvwa-open-http-redirect": ("dinamico", "redirecionamento", "laudo de validar_dvwa_http.py"),
        "dvwa-exposed-mysql": ("dinamico", "porta_do_banco",
                               "exige o manifesto Kubernetes dos autores; não reproduzível localmente"),
    },
    "teastore": {
        "ts-db-reset-unauth": ("dinamico", "funcao_critica_sem_autenticacao", ""),
        "ts-output-encoding": ("sem_modelo", "xss", "confirmar exige enviar marcação: manual"),
        "ts-tls-trust-all": ("configuracao", "use_https",
                             "USE_HTTPS ausente da implantação de referência"),
    },
    "juice-shop": {
        "js-exposed-metrics": ("dinamico", "acesso_sem_autenticacao", ""),
        "js-dom-xss": ("sem_modelo", "xss", "confirmar exige payload no navegador: manual"),
        "js-reflected-xss": ("sem_modelo", "xss", "confirmar exige payload no navegador: manual"),
        "js-rce-b2b": ("excluido", "rce", "o teste oficial tem efeito de negação de serviço"),
    },
}


def rodar_teastore(base, container):
    # Controle negativo extra do modelo de acesso: /profile exige sessão.
    perfil, _ = requisitar(base + "/profile")
    caso = funcao_critica_sem_autenticacao(
        base, "/dataBaseAction",
        {"categories": "5", "products": "100", "users": "100", "orders": "5", "confirm": "Confirm"},
        "/status", container, "DB is re-generating")
    caso["controle_rota_protegida"] = {"requisicao": perfil,
                                       "reprovou": perfil["http"] in (301, 302, 303, 401, 403)}
    return {"ts-db-reset-unauth": caso}


def rodar_juice(base):
    return {"js-exposed-metrics": acesso_sem_autenticacao(
        base, "/metrics", r"^# HELP ", "/api/Users")}


def reaproveitar_dvwa():
    laudo = json.loads((ETAPA / "pilotos/p4-dvwa/dvwa-http.json").read_text(encoding="utf-8"))
    return {vid: {"modelo": FILA["dvwa"][vid][1], "status": caso["status"],
                  "fonte": "pilotos/p4-dvwa/dvwa-http.json"}
            for vid, caso in laudo["casos"].items()}


def funil(resultados):
    linhas = []
    for app, casos in FILA.items():
        for vid, (categoria, modelo, nota) in casos.items():
            r = resultados.get(app, {}).get(vid)
            executado = r is not None
            linhas.append({"aplicacao": app, "vulnerability_id": vid, "categoria": categoria,
                           "modelo": modelo, "modelo_dinamico_benigno": int(categoria == "dinamico"),
                           "executado_na_config_local": int(executado),
                           "status": r["status"] if r else "nao_executada",
                           "confirmado": int(bool(r) and r["status"] == "confirmada"),
                           "observacao": nota})
    return linhas


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--teastore", default="http://127.0.0.1:18081/tools.descartes.teastore.webui")
    p.add_argument("--teastore-container", default="teastore-webui-1")
    p.add_argument("--juice", default="http://127.0.0.1:18082")
    p.add_argument("--out", type=Path, default=ETAPA / "pilotos/p4-catalogo")
    a = p.parse_args()
    for url in (a.teastore, a.juice):
        if not re.match(r"http://127\.0\.0\.1:\d+(/|$)", url):
            p.error("Use só alvos locais em 127.0.0.1.")
    a.out.mkdir(parents=True, exist_ok=True)
    resultados = {"dvwa": reaproveitar_dvwa(), "juice-shop": rodar_juice(a.juice),
                  "teastore": rodar_teastore(a.teastore, a.teastore_container)}
    for app in ("teastore", "juice-shop"):
        (a.out / f"{app}.json").write_text(json.dumps(
            {"aplicacao": app, "executado_em": datetime.now(timezone.utc).isoformat(),
             "casos": resultados[app]}, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    linhas = funil(resultados)
    with (ETAPA / "results/p4_funil.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0]))
        w.writeheader()
        w.writerows(linhas)
    for linha in linhas:
        print(f"{linha['aplicacao']:10} {linha['vulnerability_id']:24} {linha['categoria']:12} "
              f"{linha['status']}")
    for app in ("teastore", "juice-shop"):
        for vid, r in resultados[app].items():
            print(f"{vid}: critério={r['criterio_atendido']} "
                  f"controle_reprovou={r['controle_negativo']['reprovou']}")


if __name__ == "__main__":
    main()
