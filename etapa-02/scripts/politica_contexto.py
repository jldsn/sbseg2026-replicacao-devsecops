"""Avalia a P4 com contexto de execução (protocolo em docs/p4-contexto.md).

Políticas, por alvo:
  P2        nota >= 7, todas as classes (artigo)
  P3        nota >= 7, sem indiretos (artigo)
  P3*       P3 com o Deploy Gate do artigo executado: +1 bloqueio por caso confirmado pelos
            testes customizados benignos (supõe nota >= 7 para a confirmação, como o proxy 7,5
            que o artigo dá ao seu teste customizado)
  P4-reg    P3* + indiretos com nota >= 7 carregados em S1 ou S2 (definição registrada)
  P4        P3* + indiretos com nota >= 7 carregados em S1, S2, S3 (spider), na inicialização
            ou, no Juice Shop, no fluxo autenticado S4 (pós-registro)
  A1-A3     alternativas de limiar já usadas em comparar_politicas.py

A métrica principal é quantos bloqueios indiretos da P2 recaem sobre pacotes que nenhum
processo carregou. A cobertura da matriz obtida por achado indireto é coincidência de CWE e é
reportada só como contexto.
"""

import csv
from collections import Counter
from pathlib import Path

from analise_dvwa import Unidade, gravar_csv, ler_json

ETAPA = Path(__file__).resolve().parent.parent
ALVOS = {
    "dvwa": ("data/normalized/dvwa.json", 13, "results/p4_fila.csv"),
    "teastore": ("data/normalized/alvo-teastore.json", 14, "results/alvos_p4_fila.csv"),
    "juice-shop": ("data/normalized/alvo-juice-shop.json", 14, "results/alvos_p4_fila.csv"),
}
S4_JUICE = ETAPA / "pilotos/contexto/juice-shop--juice-r--s4-autenticado.txt"


def nota(u):
    return u.score or 0.0


def confirmados(app, fila):
    with (ETAPA / fila).open(encoding="utf-8-sig", newline="") as f:
        return {r["vulnerability_id"] for r in csv.DictReader(f)
                if r.get("aplicacao", app) == app and r["adiciona_bloqueio_p4_a"] == "1"}


def contexto():
    with (ETAPA / "results/contexto_execucao.csv").open(encoding="utf-8", newline="") as f:
        linhas = {r["unidade"]: r for r in csv.DictReader(f)}
    s4 = S4_JUICE.read_text(encoding="utf-8") if S4_JUICE.exists() else ""
    for r in linhas.values():
        com_login = (r["aplicacao"] == "juice-shop" and r["tipo_pacote"] == "node-pkg"
                     and f"node_modules/{r['pacote']}/" in s4)
        r["carregado_final"] = "1" if r["carregado"] == "1" or com_login else "0"
    return linhas


def medir(bloqueadas, extras):
    ids = {vid for u in bloqueadas for vid in u.vinculos} | extras
    return {"bloqueios": len(bloqueadas) + len(extras), "cobertura": len(ids),
            "indiretos_bloqueados": sum(u.classe == "indireta" for u in bloqueadas),
            "ids": "|".join(sorted(ids))}


def domina(x, y):
    return (x["bloqueios"] <= y["bloqueios"] and x["cobertura"] >= y["cobertura"]
            and (x["bloqueios"] < y["bloqueios"] or x["cobertura"] > y["cobertura"]))


def avaliar(app, ctx):
    arquivo, universo, fila = ALVOS[app]
    us = [Unidade(**u) for u in ler_json(ETAPA / arquivo)["unidades"]]
    conf = confirmados(app, fila)
    p3 = [u for u in us if nota(u) >= 7 and u.classe != "indireta"]
    ids_p3 = {u.id for u in p3}
    altos = [u for u in us if u.classe == "indireta" and nota(u) >= 7]
    faltando = [u.id for u in altos if u.id not in ctx]
    if faltando:
        raise SystemExit(f"{app}: sem contexto de execução para {faltando[:3]}")
    reg = [u for u in altos if ctx[u.id]["em_uso"] == "1"]
    fin = [u for u in altos if ctx[u.id]["carregado_final"] == "1"]
    pol = {
        "P2": medir([u for u in us if nota(u) >= 7], set()),
        "P3": medir(p3, set()),
        "P3*": medir(p3, conf),
        "P4-reg": medir(p3 + reg, conf),
        "P4": medir(p3 + fin, conf),
        # Comparação justa com A1-A3, que não têm os testes customizados da P3*.
        "P3+carregados": medir(p3 + fin, set()),
        "A1": medir([u for u in us if nota(u) >= 6 and u.classe != "indireta"], set()),
        "A2": medir(p3 + [u for u in altos if nota(u) >= 9 and u.id not in ids_p3], set()),
        "A3": medir([u for u in us if nota(u) >= 8], set()),
    }
    pares = {(ctx[u.id]["pacote"], ctx[u.id]["cve"]) for u in altos}
    pares_carr = {(ctx[u.id]["pacote"], ctx[u.id]["cve"]) for u in fin}
    faixa = Counter((("9+" if nota(u) >= 9 else "7-8.9"), ctx[u.id]["carregado_final"])
                    for u in altos)
    resumo = {
        "aplicacao": app, "indiretos_nota_7": len(altos), "carregados": len(fin),
        "nao_carregados": len(altos) - len(fin),
        "fracao_nao_carregada": round(1 - len(fin) / len(altos), 4),
        "carregados_definicao_registrada": len(reg),
        "pares_pacote_cve": len(pares), "pares_carregados": len(pares_carr),
        "faixa_7_8_carregados": faixa[("7-8.9", "1")], "faixa_7_8_total":
            faixa[("7-8.9", "1")] + faixa[("7-8.9", "0")],
        "faixa_9_carregados": faixa[("9+", "1")],
        "faixa_9_total": faixa[("9+", "1")] + faixa[("9+", "0")],
        # A1-A3 não têm as confirmações da P3*; a comparação justa é com P3+carregados.
        "alternativas_que_dominam_p3_mais_carregados": "|".join(
            k for k in ("A1", "A2", "A3") if domina(pol[k], pol["P3+carregados"])),
        "casos_p2_perdidos_pela_p4": "|".join(sorted(
            set(pol["P2"]["ids"].split("|")) - set(pol["P4"]["ids"].split("|")) - {""})),
    }
    linhas = [{"aplicacao": app, "politica": k, "universo": universo, **v} for k, v in pol.items()]
    return linhas, resumo


def main():
    ctx = contexto()
    linhas, resumos = [], []
    for app in ALVOS:
        l, r = avaliar(app, ctx)
        linhas += l
        resumos.append(r)
    gravar_csv(ETAPA / "results/p4_contexto_politicas.csv", linhas)
    gravar_csv(ETAPA / "results/p4_contexto_resumo.csv", resumos)
    for x in linhas:
        print(f"{x['aplicacao']:10} {x['politica']:7} {x['bloqueios']:>4} bloqueios · "
              f"{x['cobertura']:>2}/{x['universo']} · indiretos bloqueados {x['indiretos_bloqueados']}")
    for r in resumos:
        print(r)


if __name__ == "__main__":
    main()
