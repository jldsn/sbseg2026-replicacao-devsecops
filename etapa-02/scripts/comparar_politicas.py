"""Compara a P4 com alternativas simples nos três alvos (protocolo em docs/p4-avaliacao.md).

Políticas: P2, P3 (referências), A1 (P3 limiar 6), A2 (P3 + indiretos >= 9), A3 (P2 limiar 8),
A4 (P3 + todas as unidades indiretas dos casos da fila, sem teste), P4 (P3 + confirmações
reais) e P4-teto (todos os casos da fila confirmados).

Métricas: bloqueios, cobertura bruta (como no artigo) e cobertura sustentada (caso bloqueado
por unidade direta para aquele caso ou confirmado pela P4). Antes de avaliar as políticas
novas, o script confere que reproduz os números já publicados.
"""

import argparse
import csv
from pathlib import Path

from analise_dvwa import Unidade, gravar_csv, ler_json

ETAPA = Path(__file__).resolve().parent.parent
ALVOS = {
    "dvwa": {"unidades": "data/normalized/dvwa.json", "universo": 13,
             "fila": "results/p4_fila.csv", "originais": (5, 80, 56)},
    "teastore": {"unidades": "data/normalized/alvo-teastore.json", "universo": 14,
                 "fila": "results/alvos_p4_fila.csv", "originais": (32, 262, 139)},
    "juice-shop": {"unidades": "data/normalized/alvo-juice-shop.json", "universo": 14,
                   "fila": "results/alvos_p4_fila.csv", "originais": (12, 28, 9)},
}
ORDEM = ("P2", "P3", "A1", "A2", "A3", "A4", "A4c", "P4", "P4-teto")
DESCRICAO = {
    "P2": "Nota >= 7, todas as classes", "P3": "Nota >= 7, sem indiretos",
    "A1": "P3 com limiar 6", "A2": "P3 + indiretos com nota >= 9",
    "A3": "P2 com limiar 8", "A4": "P3 + indiretos dos casos da fila, sem teste",
    "A4c": "P3 + indiretos só dos casos que a P4 confirmou, sem teste (pós-registro)",
    "P4": "P3 + casos da fila confirmados", "P4-teto": "P3 + todos os casos da fila",
}
ALTERNATIVAS = ("A1", "A2", "A3", "A4")


def nota(u):
    return u.score or 0.0


def carregar(app):
    cfg = ALVOS[app]
    dados = ler_json(ETAPA / cfg["unidades"])["unidades"]
    unidades = [Unidade(**u) for u in dados]
    fila, confirmados = [], set()
    with (ETAPA / cfg["fila"]).open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("aplicacao", app) != app:
                continue
            if "entra_na_fila_p4" in row and row["entra_na_fila_p4"] != "1":
                continue
            fila.append(row["vulnerability_id"])
            if row["adiciona_bloqueio_p4_a"] == "1":
                confirmados.add(row["vulnerability_id"])
    return unidades, fila, confirmados, cfg["universo"]


def metricas(bloqueadas, extras, universo):
    bruta = {vid for u in bloqueadas for vid in u.vinculos} | extras
    sustentada = {vid for u in bloqueadas for vid, c in u.vinculos.items() if c == "direta"}
    sustentada |= extras
    return {"bloqueios": len(bloqueadas) + len(extras), "cobertura_bruta": len(bruta),
            "cobertura_sustentada": len(sustentada), "universo": universo,
            "ids_bruta": "|".join(sorted(bruta)), "ids_sustentada": "|".join(sorted(sustentada))}


def uniforme(us, limiar):
    return [u for u in us if nota(u) >= limiar]


def progressiva(us, limiar):
    return [u for u in us if nota(u) >= limiar and u.classe != "indireta"]


def politicas(us, fila, confirmados, universo):
    p3 = progressiva(us, 7)
    ids_p3 = {u.id for u in p3}
    fila_set = set(fila)
    a2 = p3 + [u for u in us if u.classe == "indireta" and nota(u) >= 9 and u.id not in ids_p3]
    def sem_teste(alvo):
        return p3 + [u for u in us if u.id not in ids_p3
                     and any(c == "indireta" and vid in alvo for vid, c in u.vinculos.items())]
    a4, a4c = sem_teste(fila_set), sem_teste(set(confirmados))
    return {
        "P2": metricas(uniforme(us, 7), set(), universo),
        "P3": metricas(p3, set(), universo),
        "A1": metricas(progressiva(us, 6), set(), universo),
        "A2": metricas(a2, set(), universo),
        "A3": metricas(uniforme(us, 8), set(), universo),
        "A4": metricas(a4, set(), universo),
        # Fora da lista registrada: compara casos iguais aos da P4 (ver p4-avaliacao.md).
        "A4c": metricas(a4c, set(), universo),
        "P4": metricas(p3, set(confirmados), universo),
        "P4-teto": metricas(p3, fila_set, universo),
    }


def conferir_reproducao(app, us, universo):
    p1, p2, p3 = (len(uniforme(us, 9)), len(uniforme(us, 7)), len(progressiva(us, 7)))
    esperado = ALVOS[app]["originais"]
    if (p1, p2, p3) != esperado:
        raise SystemExit(f"{app}: P1/P2/P3 = {(p1, p2, p3)}, esperado {esperado}.")
    if app == "dvwa":
        return
    with (ETAPA / "results/alvos_limiares.csv").open(encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row["aplicacao"] != app:
                continue
            limiar = int(row["limiar"])
            sel = uniforme(us, limiar) if row["politica"] == "uniforme" else progressiva(us, limiar)
            m = metricas(sel, set(), universo)
            obtido = (m["bloqueios"], m["cobertura_bruta"])
            publicado = (int(row["bloqueios"]), int(row["cobertura_bloqueante"]))
            if obtido != publicado:
                raise SystemExit(f"{app} {row['politica']} {limiar}: {obtido} != {publicado}.")


def domina(x, y, chave):
    return (x["bloqueios"] <= y["bloqueios"] and x[chave] >= y[chave]
            and (x["bloqueios"] < y["bloqueios"] or x[chave] > y[chave]))


def fracao(num, den):
    return round(num / den, 4) if den else None


def executar(destino):
    linhas, dominancia, funil = [], [], []
    for app in ALVOS:
        us, fila, confirmados, universo = carregar(app)
        conferir_reproducao(app, us, universo)
        res = politicas(us, fila, confirmados, universo)
        p2, p3 = res["P2"], res["P3"]
        for nome in ORDEM:
            m = res[nome]
            linhas.append({
                "aplicacao": app, "politica": nome, "descricao": DESCRICAO[nome],
                "bloqueios": m["bloqueios"], "cobertura_bruta": m["cobertura_bruta"],
                "cobertura_sustentada": m["cobertura_sustentada"], "universo": universo,
                "recuperacao_bruta": fracao(m["cobertura_bruta"] - p3["cobertura_bruta"],
                                            p2["cobertura_bruta"] - p3["cobertura_bruta"]),
                # A razão com a P2 fica indefinida: nos três alvos a P2 tem a mesma
                # cobertura sustentada da P3. Reporta-se o ganho absoluto.
                "ganho_sustentado": m["cobertura_sustentada"] - p3["cobertura_sustentada"],
                "custo": fracao(m["bloqueios"] - p3["bloqueios"], p2["bloqueios"] - p3["bloqueios"]),
                "testes_exigidos": len(fila) if nome.startswith("P4") else 0,
                "ids_cobertura_bruta": m["ids_bruta"],
                "ids_cobertura_sustentada": m["ids_sustentada"],
            })
        for alt in ALTERNATIVAS:
            dominancia.append({
                "aplicacao": app, "alternativa": alt,
                "alternativa_domina_p4_bruta": int(domina(res[alt], res["P4"], "cobertura_bruta")),
                "alternativa_domina_p4_sustentada": int(
                    domina(res[alt], res["P4"], "cobertura_sustentada")),
                "p4_domina_alternativa_bruta": int(domina(res["P4"], res[alt], "cobertura_bruta")),
                "p4_domina_alternativa_sustentada": int(
                    domina(res["P4"], res[alt], "cobertura_sustentada")),
            })
        funil.append({"aplicacao": app, "fila": len(fila), "confirmados": len(confirmados),
                      "ids_fila": "|".join(fila), "ids_confirmados": "|".join(sorted(confirmados))})
    gravar_csv(destino / "p4_comparacao.csv", linhas)
    gravar_csv(destino / "p4_dominancia.csv", dominancia)
    sustenta = not any(d["alternativa_domina_p4_sustentada"] for d in dominancia)
    for d in dominancia:
        if d["alternativa_domina_p4_bruta"] or d["alternativa_domina_p4_sustentada"]:
            print(f"{d['aplicacao']}: {d['alternativa']} domina a P4 "
                  f"(bruta={d['alternativa_domina_p4_bruta']}, "
                  f"sustentada={d['alternativa_domina_p4_sustentada']})")
    print("Regra registrada (nenhuma alternativa domina a P4 em cobertura sustentada):",
          "SE SUSTENTA" if sustenta else "NÃO SE SUSTENTA")
    return linhas, dominancia


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ETAPA / "results")
    executar(parser.parse_args().out)


if __name__ == "__main__":
    main()
