"""Sorteia a amostra estratificada da auditoria manual do coletor (docs/p4-auditoria.md).

Unidade: par distinto (pacote, CVE) entre os achados indiretos com nota >= 7. A classificação
usada é a final (carregado_final de politica_contexto.py). Semente fixa.
"""

import csv
import random
from pathlib import Path

from politica_contexto import contexto

ETAPA = Path(__file__).resolve().parent.parent
SEMENTE = 20261123
PEDIDO = {("nao_carregado", "dvwa"): 4, ("nao_carregado", "teastore"): 6,
          ("carregado", "dvwa"): 3, ("carregado", "teastore"): 3, ("carregado", "juice-shop"): 4}


def main():
    ctx = contexto()
    pares = {}
    for r in ctx.values():
        if float(r["score"] or 0) < 7:
            continue
        chave = (r["aplicacao"], r["pacote"], r["cve"])
        p = pares.setdefault(chave, {"aplicacao": r["aplicacao"], "pacote": r["pacote"],
                                     "cve": r["cve"], "tipo_pacote": r["tipo_pacote"],
                                     "estrato": "carregado" if r["carregado_final"] == "1"
                                     else "nao_carregado", "unidades": [], "containers": set()})
        p["unidades"].append(r["unidade"])
        p["containers"].update(r["containers"].split("|"))
    rng = random.Random(SEMENTE)
    amostra = []
    for (estrato, app), n in PEDIDO.items():
        celula = sorted((p for p in pares.values()
                         if p["estrato"] == estrato and p["aplicacao"] == app),
                        key=lambda p: (p["pacote"], p["cve"]))
        amostra += rng.sample(celula, min(n, len(celula)))
    destino = ETAPA / "results/auditoria_amostra.csv"
    # Preserva julgamentos já registrados: rodar o sorteio de novo não apaga a auditoria.
    anteriores = {}
    if destino.exists():
        with destino.open(encoding="utf-8", newline="") as f:
            anteriores = {(r["aplicacao"], r["pacote"], r["cve"]): r for r in csv.DictReader(f)}
    with destino.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["estrato", "aplicacao", "pacote", "cve", "tipo_pacote",
                                          "containers", "unidades", "julgamento", "evidencia"])
        w.writeheader()
        for p in amostra:
            w.writerow({"estrato": p["estrato"], "aplicacao": p["aplicacao"], "pacote": p["pacote"],
                        "cve": p["cve"], "tipo_pacote": p["tipo_pacote"],
                        "containers": "|".join(sorted(p["containers"])),
                        "unidades": "|".join(p["unidades"]),
                        "julgamento": anteriores.get((p["aplicacao"], p["pacote"], p["cve"]),
                                                     {}).get("julgamento", ""),
                        "evidencia": anteriores.get((p["aplicacao"], p["pacote"], p["cve"]),
                                                    {}).get("evidencia", "")})
    for p in amostra:
        print(p["estrato"], p["aplicacao"], p["pacote"], p["cve"])


if __name__ == "__main__":
    main()
