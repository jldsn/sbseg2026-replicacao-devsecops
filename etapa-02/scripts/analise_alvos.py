"""Aplica o modelo direto/indireto, P1–P3, sensibilidade e fila da P4 a novos alvos.

Alvos: TeaStore 1.4.2 (microsserviços Java, não intencionalmente vulnerável) e Juice Shop
19.0.0 (matriz ampliada a partir dos desafios oficiais). As regras seguem o artigo:

* Semgrep (Commit): direto quando o arquivo do achado pertence ao caso e o CWE coincide.
* Trivy FS (Commit) e Trivy Image (Build): CVE cujo CWE coincide com caso APP é indireta.
* Trivy Image: por imagem, agregados de SO em fim de suporte (EOSL), de pacotes com correção
  e das demais ocorrências, com CVSS máximo, como na DVWA.
* Checkov (Build): direto quando o check está listado no caso INFRA.
* ZAP passivo e ativo (Deploy): direto quando CWE e rota coincidem.
Notas proxy iguais às do artefato dos autores. Sem severidade no Checkov, 5,0.
"""

import argparse
import csv
import itertools
import json
import random
import statistics
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path

from analise_dvwa import LIMIARES, ORIGINAIS, Unidade, avaliar, classe_global, gravar_csv, ler_json
from politica_p4 import Validacao, bloqueia_confirmacao, ler_validacoes
from resumir_pilotos import cwes_de_semgrep, score_trivy

ETAPA = Path(__file__).resolve().parent.parent
PROXY = {"ERROR": 7.5, "WARNING": 5.0, "INFO": 3.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 3.0,
         "CRITICAL": 9.5, "INFORMATIONAL": 0.0}
ORIGENS_PROXY = {"semgrep_error", "semgrep_warning", "semgrep_info", "proxy_checkov",
                 "proxy_zap_baseline", "proxy_zap_active"}
LIMIAR = 7
SEMENTE = 20261122
AMOSTRAS = 5_000
ALVOS = {
    "teastore": {
        "versao": "1.4.2", "commit": "14648b79406db9be0cbbbc1620dd6a688b74109c",
        "semgrep": "coletas/teastore/semgrep.json",
        "checkov": "coletas/teastore/checkov.json",
        "trivy_fs": "coletas/teastore/trivy/fs.json",
        # Regra única de escopo: só o que a implantação de referência
        # (examples/kubernetes/teastore-clusterip.yaml) executa. Ficam fora o harness e2e
        # e os utilitários Kieker, usados apenas no compose de monitoramento.
        "excluir": ("e2e-tests/", "kieker"),
        "imagens": sorted(f"coletas/teastore/trivy/{p.name}"
                          for p in (ETAPA / "coletas/teastore/trivy").glob("image-*.json")),
        "zap_passivo": "pilotos/zap/teastore-passivo.json", "zap_ativo": None,
    },
    "juice-shop": {
        "versao": "19.0.0", "commit": "36870cbbdfe7864698e1adf644c7bf772f67ebb7",
        "semgrep": "coletas/juice-shop/semgrep.json",
        "checkov": "pilotos/checkov/juice-shop.json",
        "trivy_fs": "pilotos/trivy/juice-shop-fs.json",
        # Mesma regra: testes unitários e biblioteca de terceiros copiada em assets.
        "excluir": (".spec.ts", "frontend/src/assets/private/"),
        "imagens": ["pilotos/trivy/juice-shop-image.json"],
        "zap_passivo": "pilotos/zap/juice-shop-passivo.json",
        "zap_ativo": "pilotos/zap/juice-shop-ativo.json",
    },
}


def fora_do_escopo(caminho, cfg):
    return any(p in caminho for p in cfg["excluir"])


def ler_matriz(app, somente_primario=False):
    """somente_primario usa só o primeiro CWE de cada caso (teste de robustez)."""
    with (ETAPA / "data/ground_truth" / f"{app}.csv").open(encoding="utf-8-sig") as f:
        linhas = list(csv.DictReader(f))
    for v in linhas:
        cwes = v["cwe"].split("|")
        v["cwes"] = set(cwes[:1] if somente_primario else cwes)
        v["arquivos"] = [a for a in v["arquivos_sast"].split("|") if a]
        v["checks"] = set(filter(None, v["checkov_ids"].split("|")))
    return linhas


def ref(path, ponteiro):
    return f"{path}#{ponteiro}"


def nova(app, n, ferramenta, camada, estagio, vinculos, score, origem, sev, ident, cwes, referencia,
         grao="individual"):
    return Unidade(f"{app}-{n:04d}", ferramenta, camada, estagio, classe_global(vinculos), score,
                   origem, sev, ident, tuple(sorted(cwes)), vinculos, referencia, grao)


def indiretos_por_cwe(matriz, cwes):
    return {v["vulnerability_id"]: "indireta" for v in matriz
            if v["camada"] == "APP" and v["cwes"] & set(cwes)}


def carregar_checkov(path):
    dados = ler_json(ETAPA / path)
    blocos = dados if isinstance(dados, list) else [dados]
    for b in blocos:
        for i, c in enumerate(b["results"]["failed_checks"]):
            yield b.get("check_type", "dockerfile"), i, c


def normalizar(app, cfg, matriz):
    us = []
    add = lambda *a, **k: us.append(nova(app, len(us) + 1, *a, **k))  # noqa: E731
    bruto = Counter()
    # SAST
    for i, f in enumerate(ler_json(ETAPA / cfg["semgrep"])["results"]):
        if fora_do_escopo(f["path"], cfg):
            bruto["fora_do_escopo"] += 1
            continue
        bruto["Semgrep"] += 1
        cwes = cwes_de_semgrep(f)
        sev = f["extra"]["severity"]
        vs = {v["vulnerability_id"]: "direta" for v in matriz if v["camada"] == "APP"
              and v["cwes"] & set(cwes) and any(a in f["path"] for a in v["arquivos"])}
        add("Semgrep", "APP", "commit", vs, PROXY.get(sev), f"semgrep_{sev.lower()}", sev,
            f["check_id"].split(".")[-1], cwes, ref(cfg["semgrep"], f"/results/{i}"))
    # SCA
    fs = ler_json(ETAPA / cfg["trivy_fs"]).get("Results") or []
    for i, r in enumerate(fs):
        if fora_do_escopo(r["Target"], cfg):
            bruto["fora_do_escopo"] += len(r.get("Vulnerabilities") or [])
            continue
        for j, v in enumerate(r.get("Vulnerabilities") or []):
            bruto["Trivy FS (SCA)"] += 1
            cwes = v.get("CweIDs") or []
            add("Trivy FS (SCA)", "APP", "commit", indiretos_por_cwe(matriz, cwes), score_trivy(v),
                "cvss_v3", v.get("Severity"), v["VulnerabilityID"], cwes,
                ref(cfg["trivy_fs"], f"/Results/{i}/Vulnerabilities/{j}"))
    # IaC
    for tipo, i, c in carregar_checkov(cfg["checkov"]):
        bruto["Checkov"] += 1
        vs = {v["vulnerability_id"]: "direta" for v in matriz
              if v["criterio_infra"] == "checkov" and c["check_id"] in v["checks"]}
        sev = c.get("severity")
        add("Checkov", "INFRA", "build", vs, PROXY.get((sev or "MEDIUM").upper(), 5.0),
            "proxy_checkov", sev or "MEDIUM", c["check_id"], (),
            ref(cfg["checkov"], f"/{tipo}/failed_checks/{i}"))
    # Container
    eosl = [v["vulnerability_id"] for v in matriz if v["criterio_infra"] == "agregado_eosl"]
    fix = [v["vulnerability_id"] for v in matriz if v["criterio_infra"] == "agregado_fixable"]
    composicao = []
    for path in cfg["imagens"]:
        d = ler_json(ETAPA / path)
        imagem = Path(path).stem
        os_eosl = bool((d.get("Metadata", {}).get("OS") or {}).get("EOSL"))
        todas, fixaveis, outras = [], [], []
        for i, r in enumerate(d.get("Results") or []):
            for j, v in enumerate(r.get("Vulnerabilities") or []):
                bruto["Trivy Image"] += 1
                cwes = v.get("CweIDs") or []
                s = score_trivy(v)
                todas.append(s)
                if v.get("FixedVersion"):
                    fixaveis.append(s)
                vs = indiretos_por_cwe(matriz, cwes)
                if vs:
                    add("Trivy Image", "INFRA", "build", vs, s, "cvss_v3", v.get("Severity"),
                        v["VulnerabilityID"], cwes, ref(path, f"/Results/{i}/Vulnerabilities/{j}"))
                else:
                    outras.append(s)
        grupos = [("eosl", todas if os_eosl and eosl else [], eosl),
                  ("fixable", fixaveis if fix else [], fix), ("outras", outras, [])]
        for nome, scores, ids in grupos:
            validos = [s for s in scores if s is not None]
            if not scores:
                continue
            composicao.append({"aplicacao": app, "imagem": imagem, "grupo": nome,
                               "ocorrencias": len(scores), "com_cvss": len(validos),
                               "maximo": max(validos, default=None),
                               "media": round(statistics.mean(validos), 4) if validos else None,
                               "mediana": statistics.median(validos) if validos else None})
            add("Trivy Image", "INFRA", "build", {vid: "direta" for vid in ids},
                max(validos, default=None), "trivy_max", None, f"{imagem}:{nome}", (), path,
                grao=f"aggregate_{nome}")
    # DAST
    for chave, origem in (("zap_passivo", "proxy_zap_baseline"), ("zap_ativo", "proxy_zap_active")):
        if not cfg[chave]:
            continue
        alertas = ler_json(ETAPA / cfg[chave])["alerts"]
        por_tipo = defaultdict(list)
        for i, a in enumerate(alertas):
            bruto[f"ZAP {chave[4:]}"] += 1
            por_tipo[(a["pluginId"], a["alert"])].append((i, a))
        for (plugin, nome), inst in por_tipo.items():
            a = inst[0][1]
            cwes = [f"CWE-{a['cweid']}"] if a["cweid"] not in ("-1", "0") else []
            vs = {v["vulnerability_id"]: "direta" for v in matriz if v["camada"] == "APP"
                  and v["cwes"] & set(cwes) and v["rota_dast"]
                  and any(v["rota_dast"] in x["url"] for _, x in inst)}
            add(f"OWASP ZAP ({chave[4:]})", "APP", "deploy", vs, PROXY.get(a["risk"].upper()),
                origem, a["risk"], plugin, cwes, ref(cfg[chave], f"/alerts/{inst[0][0]}"))
    return us, bruto, composicao


def ids(r):
    return set(filter(None, r["ids_bloqueados"].split("|")))


def cobertura_por_caso(app, us, matriz):
    res = {p: ids(avaliar(us, p, l, universo=len(matriz))) for p, l in ORIGINAIS}
    linhas = []
    for v in matriz:
        vid = v["vulnerability_id"]
        c = Counter(u.vinculos.get(vid) for u in us)
        status = "direta" if c["direta"] else "apenas indireta" if c["indireta"] else "nao detectada"
        ferramentas = sorted({u.ferramenta for u in us if vid in u.vinculos})
        linhas.append({"aplicacao": app, "vulnerability_id": vid, "nome": v["nome"],
                       "cwe": v["cwe"], "camada": v["camada"], "fonte": v["fonte"],
                       "diretas": c["direta"], "indiretas": c["indireta"], "status": status,
                       "ferramentas": "|".join(ferramentas),
                       **{f"bloqueia_{p}": int(vid in res[p]) for p, _ in ORIGINAIS}})
    return linhas


def grupos_proxy(us):
    grupos = defaultdict(list)
    for u in us:
        if u.origem_score in ORIGENS_PROXY and u.score:
            grupos[(u.origem_score, u.score)].append(u)
    return grupos


def reducao(p2, p3):
    return round(1 - p3 / p2, 4) if p2 else None


def par(us, n, scores):
    return (avaliar(us, "P2", LIMIAR, scores, universo=n), avaliar(us, "P3", LIMIAR, scores, universo=n))


def sensibilidade(app, us, n, amostras, semente):
    grupos = grupos_proxy(us)
    p2, p3 = par(us, n, {})
    base = reducao(p2["bloqueios"], p3["bloqueios"])
    tornado = []
    for (origem, nota), membros in sorted(grupos.items()):
        linha = {"aplicacao": app, "grupo": f"{origem}={nota}", "unidades": len(membros),
                 "reducao_base": base}
        for lado, x in (("baixa", max(0.0, nota - 2)), ("alta", min(10.0, nota + 2))):
            q2, q3 = par(us, n, {u.id: x for u in membros})
            linha |= {f"nota_{lado}": x, f"p2_{lado}": q2["bloqueios"], f"p3_{lado}": q3["bloqueios"],
                      f"p2_cob_{lado}": q2["cobertura_bloqueante"],
                      f"p3_cob_{lado}": q3["cobertura_bloqueante"],
                      f"reducao_{lado}": reducao(q2["bloqueios"], q3["bloqueios"])}
        tornado.append(linha)
    resumo = []
    for cenario, faixa in (("base_mais_menos_2", lambda b: (max(0.0, b - 2), min(10.0, b + 2))),
                           ("amplo_1_a_10", lambda b: (1.0, 10.0))):
        rng = random.Random(semente)
        reds, perdas, p3s = [], [], []
        for _ in range(amostras):
            scores = {}
            for (origem, nota), membros in grupos.items():
                x = round(rng.uniform(*faixa(nota)), 2)
                scores.update({u.id: x for u in membros})
            q2, q3 = par(us, n, scores)
            reds.append(reducao(q2["bloqueios"], q3["bloqueios"]) or 0.0)
            perdas.append(q2["cobertura_bloqueante"] - q3["cobertura_bloqueante"])
            p3s.append(q3["bloqueios"])
        q = statistics.quantiles(reds, n=20, method="inclusive")
        resumo.append({"aplicacao": app, "cenario": cenario, "amostras": amostras, "semente": semente,
                       "reducao_base": base, "reducao_min": min(reds), "reducao_p5": round(q[0], 4),
                       "reducao_mediana": round(statistics.median(reds), 4),
                       "reducao_p95": round(q[18], 4), "reducao_max": max(reds),
                       "fracao_25_35pct": round(sum(.25 <= r <= .35 for r in reds) / amostras, 4), "perda_cobertura_min": min(perdas),
                       "perda_cobertura_max": max(perdas), "p3_bloqueios_min": min(p3s),
                       "p3_bloqueios_max": max(p3s)})
    return tornado, resumo


def agregacoes(app, us, n, composicao):
    linhas = []
    por_ref = {(c["imagem"], c["grupo"]): c for c in composicao}
    for metodo in ("maximo", "media", "mediana"):
        scores = {}
        for u in us:
            if u.origem_score == "trivy_max":
                imagem, grupo = u.identificador_scanner.split(":")
                scores[u.id] = por_ref[(imagem, grupo)][metodo]
        for p, l in ORIGINAIS:
            linhas.append({"aplicacao": app, "agregacao": f"por_imagem_{metodo}",
                           **avaliar(us, p, l, scores, universo=n)})
    # Um agregado por grupo no sistema inteiro, em vez de um por imagem (máximo).
    sistema, vistos = [], set()
    for u in us:
        if u.origem_score != "trivy_max":
            sistema.append(u)
            continue
        grupo = u.identificador_scanner.split(":")[1]
        membros = [x for x in us if x.origem_score == "trivy_max"
                   and x.identificador_scanner.endswith(f":{grupo}")]
        if grupo in vistos:
            continue
        vistos.add(grupo)
        sistema.append(Unidade(**{**asdict(u), "id": f"{app}-sistema-{grupo}",
                                  "score": max((m.score for m in membros if m.score is not None),
                                               default=None),
                                  "identificador_scanner": f"sistema:{grupo}"}))
    for p, l in ORIGINAIS:
        linhas.append({"aplicacao": app, "agregacao": "sistema_maximo",
                       **avaliar(sistema, p, l, universo=n)})
    return linhas


def fila_p4(app, us, matriz, laudos=None):
    n = len(matriz)
    r2 = avaliar(us, "P2", LIMIAR, universo=n)
    p2 = ids(r2)
    p3 = avaliar(us, "P3", LIMIAR, universo=n)
    bloq = ids(p3)
    fila = []
    candidatos_dict = {}
    for v in matriz:
        vid = v["vulnerability_id"]
        if vid in bloq:
            continue
        ind = [u.id for u in us if u.vinculos.get(vid) == "indireta"]
        dire = [u.id for u in us if u.vinculos.get(vid) == "direta"]
        motivo = ("apenas_indireta" if ind and not dire else "perda_p2_p3" if vid in p2
                  else "abaixo_do_limiar" if dire else "nao_detectada")
        entra = motivo in ("apenas_indireta", "perda_p2_p3")
        if entra:
            candidatos_dict[vid] = (v["nome"], ind, dire, motivo)
        fila.append({"aplicacao": app, "vulnerability_id": vid, "nome": v["nome"],
                     "motivo": motivo, "entra_na_fila_p4": int(entra),
                     "sinais_indiretos": len(ind), "sinais_diretos": len(dire),
                     "rota_dast": v["rota_dast"]})
    validacoes = ler_validacoes(laudos, candidatos_dict) if laudos and laudos.exists() else {}
    novas_a, novas_b, novas_b_alt = set(), set(), set()
    for linha in fila:
        if not linha["entra_na_fila_p4"]:
            linha.update(status="nao_aplicavel", evidencia="", score_confirmacao="",
                         adiciona_bloqueio_p4_a=0, adiciona_bloqueio_p4_b=0,
                         adiciona_bloqueio_p4_b_alt=0)
            continue
        v = validacoes.get(linha["vulnerability_id"], Validacao())
        a = bloqueia_confirmacao(v, "P4-A")
        b = bloqueia_confirmacao(v, "P4-B")
        b_alt = bloqueia_confirmacao(v, "P4-B-alt")
        linha.update(status=v.status, evidencia=v.evidencia,
                     score_confirmacao=v.score_confirmacao,
                     adiciona_bloqueio_p4_a=int(a), adiciona_bloqueio_p4_b=int(b),
                     adiciona_bloqueio_p4_b_alt=int(b_alt))
        if a:
            novas_a.add(linha["vulnerability_id"])
        if b:
            novas_b.add(linha["vulnerability_id"])
        if b_alt:
            novas_b_alt.add(linha["vulnerability_id"])
    resultados = []
    for p, novas in [("P3", set()), ("P4-A", novas_a), ("P4-B", novas_b), ("P4-B-alt", novas_b_alt)]:
        resultados.append({"aplicacao": app, "politica": p, "base_bloqueios": p3["bloqueios"],
                           "bloqueios_adicionais_no_deploy": len(novas),
                           "decisoes_simuladas": p3["bloqueios"] + len(novas),
                           "cobertura_bloqueante": len(bloq | novas), "vulnerabilidades_matriz": n,
                           "novos_ids_bloqueados": "|".join(sorted(novas)),
                           "referencia_p2_bloqueios": r2["bloqueios"],
                           "referencia_p2_cobertura": len(p2),
                           "fonte_validacoes": "nao_aplicavel" if p == "P3"
                           else "evidencias_informadas" if laudos else "sem_laudos"})
    candidatos = list(candidatos_dict)
    cond = [{"aplicacao": app, "confirmacoes": k, "decisoes_simuladas": p3["bloqueios"] + k,
             "cobertura_bloqueante": len(bloq) + k, "vulnerabilidades_matriz": n,
             "referencia_p2_bloqueios": r2["bloqueios"], "referencia_p2_cobertura": len(p2)}
            for k in range(len(candidatos) + 1)]
    return fila, resultados, cond


def executar(destino, amostras, semente):
    tabelas = defaultdict(list)
    for app, cfg in ALVOS.items():
        matriz = ler_matriz(app)
        n = len(matriz)
        us, bruto, composicao = normalizar(app, cfg, matriz)
        (ETAPA / "data/normalized" / f"alvo-{app}.json").write_text(json.dumps(
            {"aplicacao": app, "versao": cfg["versao"], "commit": cfg["commit"],
             "unidades": [asdict(u) for u in us]}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
        classes = Counter(u.classe for u in us)
        tabelas["alvos_composicao"].append({
            "aplicacao": app, "versao": cfg["versao"], "ocorrencias_brutas": sum(bruto.values()),
            **{f"bruto_{k}": bruto[k] for k in ("Semgrep", "Trivy FS (SCA)", "Checkov",
                                                 "Trivy Image", "ZAP passivo", "ZAP ativo",
                                                 "fora_do_escopo")},
            "unidades": len(us),
            "diretas": classes["direta"], "indiretas": classes["indireta"],
            "sem_matriz": classes["sem_matriz"], "casos_matriz": n,
            "casos_detectados": len({vid for u in us for vid in u.vinculos}),
            "casos_com_direta": len({vid for u in us for vid, c in u.vinculos.items() if c == "direta"}),
        })
        tabelas["alvos_trivy_composicao"] += composicao
        for p, l in ORIGINAIS:
            tabelas["alvos_politicas"].append({"aplicacao": app, **avaliar(us, p, l, universo=n)})
        for l in LIMIARES:
            for p in ("uniforme", "progressiva"):
                tabelas["alvos_limiares"].append({"aplicacao": app, **avaliar(us, p, l, universo=n)})
        tabelas["alvos_cobertura"] += cobertura_por_caso(app, us, matriz)
        # Robustez: as listas de CWE de alguns casos foram fixadas depois de ver as coletas.
        prim = ler_matriz(app, somente_primario=True)
        us_prim, _, _ = normalizar(app, cfg, prim)
        for p, l in ORIGINAIS:
            tabelas["alvos_robustez_cwe_primario"].append(
                {"aplicacao": app, "variante": "somente_cwe_primario",
                 **avaliar(us_prim, p, l, universo=n)})
        tornado, resumo = sensibilidade(app, us, n, amostras, semente)
        tabelas["alvos_sensibilidade_tornado"] += tornado
        tabelas["alvos_sensibilidade_monte_carlo"] += resumo
        tabelas["alvos_trivy_agregacao"] += agregacoes(app, us, n, composicao)
        laudos = ETAPA / "pilotos" / f"p4-{app}" / "validacoes.csv"
        fila, resultados_p4, cond = fila_p4(app, us, matriz, laudos if laudos.exists() else None)
        tabelas["alvos_p4_fila"] += fila
        tabelas["alvos_p4_resultados"] += resultados_p4
        tabelas["alvos_p4_condicionais"] += cond
    for nome, linhas in tabelas.items():
        gravar_csv(destino / f"{nome}.csv", linhas)
    for r in tabelas["alvos_politicas"]:
        print(f"{r['aplicacao']:<11} {r['politica']} {r['bloqueios']:>4} bloqueios, cobertura "
              f"{r['cobertura_bloqueante']}/{r['vulnerabilidades_matriz']} ({r['unidades']} unidades)")
    return tabelas


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ETAPA / "results")
    parser.add_argument("--amostras", type=int, default=AMOSTRAS)
    parser.add_argument("--semente", type=int, default=SEMENTE)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    executar(args.out, args.amostras, args.semente)


if __name__ == "__main__":
    main()
