"""Critério S5 da P4 (docs/p4-acoes.md): verificação mecânica de falso negativo do coletor.

Para cada contêiner e cada pacote de SO não carregado, procura dois indícios de que o pacote
roda sem aparecer no snapshot: (a) um executável dele citado em Healthcheck, Entrypoint, Cmd,
scripts de inicialização ou cron; (b) uma soname dele escrita dentro de um arquivo carregado
(dlopen sob demanda). Cada indício vira uma linha em results/p4_s5.csv. O julgamento de cada
indício (quando já examinado) fica em JULGAMENTOS, com a evidência.

Entradas: pilotos/contexto-acoes/<alvo>--s5.json e results/contexto_imagem.csv.
"""

import csv
import json
from pathlib import Path, PurePosixPath

ETAPA = Path(__file__).resolve().parent.parent
APPS = ("dvwa", "teastore", "juice-shop")

# (pacote, soname ou executável) -> (julgamento, evidência). Avaliador único.
JULGAMENTOS = {
    ("libtinfo5", "libtinfo.so.5"): (
        "falso_negativo_confirmado",
        "teastore-db: o Entrypoint é docker-entrypoint.sh (#!/bin/bash) e o bash linka "
        "libtinfo.so.5 (ldd); o bash roda na inicialização e faz exec do mysqld. Corrigido "
        "pós-registro: interpretador da inicialização e suas bibliotecas contam como carregados."),
    ("libtinfo6", "libtinfo.so.6"): (
        "falso_negativo_confirmado",
        "Serviços Java do TeaStore: catalina.sh e start.sh rodam com bash (#!/usr/bin/env bash), "
        "que linka libtinfo.so.6. Mesma correção pós-registro."),
    ("libidn2-0", "libidn2.so.0"): (
        "improvavel",
        "A glibc só abre libidn2 por dlopen para nomes internacionalizados (getaddrinfo com "
        "AI_IDN, funções idna); a JVM não pede AI_IDN. Não observado em S1-S3."),
    ("libsepol1", "libsepol.so.1"): (
        "improvavel",
        "libselinux abre libsepol só para carregar política SELinux (selinux_mkload_policy), "
        "papel do init do sistema; Apache e PHP não fazem isso."),
    ("libssl1.0.2", "libgmp.so"): (
        "nao_e_indicio",
        "Coincidência de nome: libssl1.0.2 traz o engine openssl-1.0.2/engines/libgmp.so, e a "
        "string 'libgmp.so' citada é da libgmp. O Apache usa libssl1.1."),
}

# Pacotes npm não carregados com require estático em algum arquivo: (pacote) -> julgamento.
JULGAMENTOS_NPM = {
    "diff": ("ferramenta_de_desenvolvimento",
             "Só rsn/rsnUtil (script npm 'rsn' via ts-node, verificação de snippets do projeto) e "
             "ts-node/repl; o servidor (build/server.js, routes, lib) não importa rsn."),
    "ip-address": ("ferramenta_de_instalacao",
                   "Só socks (agentes de proxy usados pelo npm na instalação); nenhum arquivo "
                   "de socks foi carregado em S1-S4."),
    "tar": ("ferramenta_de_instalacao",
            "Só node-gyp, node-pre-gyp e sqlite3/deps/extract.js, usados para compilar ou "
            "baixar módulos nativos na instalação."),
    "tar-fs": ("ferramenta_de_instalacao", "Só prebuild-install/download.js (instalação)."),
    "lodash.set": ("ferramenta_de_build", "Só grunt-replace-json (tarefa do Grunt, no build)."),
    "picomatch": ("ferramenta_de_desenvolvimento",
                  "Só anymatch, readdirp, micromatch do grunt e tinyglobby (watchers e globs de "
                  "build); nenhum desses arquivos foi carregado em S1-S4."),
}


def vex_pacotes(app, vex_cves):
    """Nomes de pacote npm presentes no VEX registrado (pelo PURL pkg:npm/<nome>@...)."""
    nomes = set()
    for _, purl in vex_cves[app]:
        if purl.startswith("pkg:npm/"):
            nomes.add(purl.split("/", 1)[1].rsplit("@", 1)[0].replace("%40", "@"))
    return nomes


def main():
    ctx = list(csv.DictReader((ETAPA / "results/contexto_imagem.csv").open(encoding="utf-8")))
    vex_cves = {}
    for app in APPS:
        vex_cves[app] = set()
        for arq in (ETAPA / "pilotos/contexto-acoes").glob(f"vex-{app}--*-registrado.json"):
            v = json.loads(arq.read_text("utf-8"))
            vex_cves[app] |= {(s["vulnerability"]["name"], p["@id"])
                              for s in v["statements"] for p in s["products"]}
    linhas = []
    for app in APPS:
        dados = json.loads((ETAPA / f"pilotos/contexto-acoes/{app}--s5.json").read_text("utf-8"))
        for c, x in dados.items():
            do_c = [r for r in ctx if r["aplicacao"] == app and c in r["containers"].split("|")
                    and r["tipo_pacote"] in ("debian", "ubuntu")]
            nl = {r["pacote"] for r in do_c} - {r["pacote"] for r in do_c if r["carregado"] == "1"}
            nl_reg = ({r["pacote"] for r in do_c}
                      - {r["pacote"] for r in do_c if r["carregado_registrado"] == "1"})
            no_vex = {r["pacote"] for r in do_c if (r["cve"], r["purl"]) in vex_cves[app]}
            gat = {PurePosixPath(t).name for t in x["gatilhos"]} | set(x["gatilhos"])
            indicios = []
            for pk in sorted(nl_reg):
                for e in sorted(set(x["executaveis"].get(pk, [])) & gat):
                    indicios.append((pk, "executavel_em_gatilho", e, ""))
            dono = {s: pk for pk in nl_reg for s in x["sonames"].get(pk, [])}
            for s, arquivos in sorted(x["sonames_citadas"].items()):
                if s in dono:
                    indicios.append((dono[s], "soname_citada", s, "|".join(arquivos[:5])))
            for pk, tipo, chave, onde in indicios:
                julg, evid = JULGAMENTOS.get((pk, chave), ("a_examinar", ""))
                linhas.append({"aplicacao": app, "container": c, "pacote": pk, "indicio": tipo,
                               "chave": chave, "citado_em": onde,
                               # O VEX da definição registrada declarava CVE deste pacote?
                               "afetava_vex_registrado": int(pk in no_vex),
                               "carregado_apos_correcao": int(pk not in nl),
                               "julgamento": julg, "evidencia": evid})
        for c, x in dados.items():
            for pk, arquivos in sorted((x.get("requires_npm") or {}).items()):
                julg, evid = JULGAMENTOS_NPM.get(pk, ("a_examinar", ""))
                carregados = [a["arquivo"] for a in arquivos if a["arquivo_carregado"]]
                if carregados:
                    julg, evid = "a_examinar", "arquivo que importa o pacote foi carregado"
                linhas.append({"aplicacao": app, "container": c, "pacote": pk,
                               "indicio": "require_estatico", "chave": pk,
                               "citado_em": "|".join(a["arquivo"] for a in arquivos[:6]),
                               "afetava_vex_registrado": int(pk in vex_pacotes(app, vex_cves)),
                               "carregado_apos_correcao": 0,
                               "julgamento": julg, "evidencia": evid})
    destino = ETAPA / "results/p4_s5.csv"
    with destino.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0]) if linhas else ["aplicacao"])
        w.writeheader()
        w.writerows(linhas)
    for x in linhas:
        print(x["aplicacao"], x["container"], x["pacote"], x["indicio"], x["chave"],
              "corrigido" if x["carregado_apos_correcao"] else "", x["julgamento"])


if __name__ == "__main__":
    main()
