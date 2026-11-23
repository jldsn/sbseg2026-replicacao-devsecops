"""Sensibilidade de todas as notas proxy arbitrárias da DVWA, isoladas e em conjunto.

Lê apenas a base normalizada (data/normalized/dvwa.json) e não exige o artefato dos autores.
Cada grupo reúne unidades que recebem a mesma nota por um mapeamento fixo do script
original. Ao variar um grupo, todas as suas unidades mudam juntas, como mudaria o mapa.
"""

import argparse
import random
import statistics
from collections import Counter
from pathlib import Path

from analise_dvwa import ORIGINAIS, Unidade, avaliar, gravar_csv, ler_json

ETAPA = Path(__file__).resolve().parent.parent
NOTAS = (3, 4, 5, 6, 7, 7.5, 8, 9, 10)
LIMIAR = 7
AMOSTRAS = 10_000
SEMENTE = 20261122
FAIXA_ARTIGO = (0.25, 0.35)


def nivel_zap(u):
    return (u.severidade_original or "").split(" ")[0].casefold()


# Grupo -> (descrição, filtro de unidades, nota base do script original)
GRUPOS = {
    "semgrep_error": ("Semgrep ERROR -> 7,5", lambda u: u.origem_score == "semgrep_error", 7.5),
    "semgrep_warning": ("Semgrep WARNING -> 5,0", lambda u: u.origem_score == "semgrep_warning", 5.0),
    "checkov": ("Checkov sem severidade -> MEDIUM -> 5,0",
                lambda u: u.origem_score == "proxy_checkov", 5.0),
    "zap_baseline_medium": ("ZAP Baseline Medium -> 5,0",
                            lambda u: u.origem_score == "proxy_zap_baseline"
                            and nivel_zap(u) == "medium", 5.0),
    "zap_baseline_low": ("ZAP Baseline Low -> 3,0",
                         lambda u: u.origem_score == "proxy_zap_baseline"
                         and nivel_zap(u) == "low", 3.0),
    "teste_credenciais": ("Brute Force e Default Credentials -> 7,5",
                          lambda u: u.origem_score == "proxy_teste_credenciais", 7.5),
}
CENARIOS_MC = {
    "base_mais_menos_2": lambda base: (max(0.0, base - 2), min(10.0, base + 2)),
    "amplo_1_a_10": lambda base: (1.0, 10.0),
}


def membros(unidades):
    saida = {g: [u for u in unidades if filtro(u)] for g, (_, filtro, _) in GRUPOS.items()}
    for g, (_, _, base) in GRUPOS.items():
        assert saida[g], f"Grupo vazio: {g}"
        assert all(u.score == base for u in saida[g]), f"Nota base divergente em {g}"
    return saida


def scores_para(grupos, notas):
    return {u.id: notas[g] for g, us in grupos.items() if g in notas for u in us}


def reducao(p2, p3):
    return round(1 - p3 / p2, 4) if p2 else None


def par_p2_p3(unidades, scores):
    p2 = avaliar(unidades, "P2", LIMIAR, scores)
    p3 = avaliar(unidades, "P3", LIMIAR, scores)
    return p2, p3


def individuais(unidades, grupos, base):
    linhas = []
    for g, us in grupos.items():
        for nota in NOTAS:
            scores = scores_para(grupos, {g: nota})
            for (politica, limiar), original in zip(ORIGINAIS, base):
                r = avaliar(unidades, politica, limiar, scores)
                linhas.append({
                    "grupo": g, "descricao": GRUPOS[g][0], "nota_base": GRUPOS[g][2],
                    "nota": nota, "unidades_do_grupo": len(us), **r,
                    "delta_bloqueios": r["bloqueios"] - original["bloqueios"],
                    "delta_cobertura": r["cobertura_bloqueante"] - original["cobertura_bloqueante"],
                })
    return linhas


def tornado(unidades, grupos):
    p2, p3 = par_p2_p3(unidades, {})
    ref = reducao(p2["bloqueios"], p3["bloqueios"])
    linhas = []
    for g, us in grupos.items():
        base = GRUPOS[g][2]
        lado = {}
        for nome, nota in (("baixa", max(0.0, base - 2)), ("alta", min(10.0, base + 2))):
            q2, q3 = par_p2_p3(unidades, scores_para(grupos, {g: nota}))
            lado[nome] = (nota, q2, q3, reducao(q2["bloqueios"], q3["bloqueios"]))
        linha = {"grupo": g, "descricao": GRUPOS[g][0], "unidades_do_grupo": len(us),
                 "nota_base": base, "reducao_p3_vs_p2_base": ref}
        for nome, (nota, q2, q3, red) in lado.items():
            linha |= {
                f"nota_{nome}": nota, f"p2_bloqueios_{nome}": q2["bloqueios"],
                f"p3_bloqueios_{nome}": q3["bloqueios"],
                f"p2_cobertura_{nome}": q2["cobertura_bloqueante"],
                f"p3_cobertura_{nome}": q3["cobertura_bloqueante"],
                f"reducao_{nome}": red,
            }
        linha["amplitude_reducao"] = round(
            max(linha["reducao_baixa"], linha["reducao_alta"], ref)
            - min(linha["reducao_baixa"], linha["reducao_alta"], ref), 4)
        linhas.append(linha)
    return sorted(linhas, key=lambda r: -r["amplitude_reducao"])


def percentis(valores):
    q = statistics.quantiles(valores, n=20, method="inclusive")
    return {"min": min(valores), "p5": q[0], "p25": q[4], "mediana": statistics.median(valores),
            "p75": q[14], "p95": q[18], "max": max(valores)}


def monte_carlo(unidades, grupos, amostras, semente):
    resumo, distribuicao = [], []
    for cenario, faixa in CENARIOS_MC.items():
        rng = random.Random(semente)
        medidas = {k: [] for k in ("p2_bloqueios", "p3_bloqueios", "reducao_p3_vs_p2",
                                   "p2_cobertura", "p3_cobertura", "perda_cobertura")}
        for _ in range(amostras):
            notas = {g: round(rng.uniform(*faixa(GRUPOS[g][2])), 2) for g in grupos}
            p2, p3 = par_p2_p3(unidades, scores_para(grupos, notas))
            medidas["p2_bloqueios"].append(p2["bloqueios"])
            medidas["p3_bloqueios"].append(p3["bloqueios"])
            medidas["reducao_p3_vs_p2"].append(reducao(p2["bloqueios"], p3["bloqueios"]) or 0.0)
            medidas["p2_cobertura"].append(p2["cobertura_bloqueante"])
            medidas["p3_cobertura"].append(p3["cobertura_bloqueante"])
            medidas["perda_cobertura"].append(p2["cobertura_bloqueante"] - p3["cobertura_bloqueante"])
        reds = medidas["reducao_p3_vs_p2"]
        dentro = sum(FAIXA_ARTIGO[0] <= r <= FAIXA_ARTIGO[1] for r in reds) / amostras
        for metrica, valores in medidas.items():
            resumo.append({
                "cenario": cenario, "amostras": amostras, "semente": semente, "metrica": metrica,
                **{k: round(v, 4) for k, v in percentis(valores).items()},
                "media": round(statistics.mean(valores), 4),
                "fracao_reducao_entre_25_e_35pct": round(dentro, 4) if metrica == "reducao_p3_vs_p2" else "",
            })
        contagem = Counter(round(100 * r) for r in reds)
        distribuicao.extend({"cenario": cenario, "reducao_pct": pct, "amostras": n}
                            for pct, n in sorted(contagem.items()))
    return resumo, distribuicao


def executar(base_json, saida, amostras, semente):
    unidades = [Unidade(**u) for u in ler_json(base_json)["unidades"]]
    grupos = membros(unidades)
    base = [avaliar(unidades, p, l) for p, l in ORIGINAIS]
    assert [(r["bloqueios"], r["cobertura_bloqueante"]) for r in base] == [(5, 3), (80, 11), (56, 8)]
    resumo, distribuicao = monte_carlo(unidades, grupos, amostras, semente)
    saidas = {
        "sensibilidade_proxies_individuais.csv": individuais(unidades, grupos, base),
        "sensibilidade_tornado.csv": tornado(unidades, grupos),
        "sensibilidade_monte_carlo_resumo.csv": resumo,
        "sensibilidade_monte_carlo_distribuicao.csv": distribuicao,
    }
    saida.mkdir(parents=True, exist_ok=True)
    for nome, linhas in saidas.items():
        gravar_csv(saida / nome, linhas)
    print("Grupos de notas proxy:", {g: len(us) for g, us in grupos.items()})
    for r in resumo:
        if r["metrica"] == "reducao_p3_vs_p2":
            print(f"{r['cenario']}: redução P3 vs P2 de {r['min']:.0%} a {r['max']:.0%} "
                  f"(p5 {r['p5']:.0%}, mediana {r['mediana']:.0%}, p95 {r['p95']:.0%}); "
                  f"{r['fracao_reducao_entre_25_e_35pct']:.0%} das amostras entre 25% e 35%")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=ETAPA / "data/normalized/dvwa.json")
    parser.add_argument("--out", type=Path, default=ETAPA / "results")
    parser.add_argument("--amostras", type=int, default=AMOSTRAS)
    parser.add_argument("--semente", type=int, default=SEMENTE)
    args = parser.parse_args()
    executar(args.base, args.out, args.amostras, args.semente)


if __name__ == "__main__":
    main()
