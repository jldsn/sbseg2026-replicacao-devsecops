"""Critério S4 da P4 (docs/p4-acoes.md): o Trivy suprime exatamente o que o VEX declara?

Lê as quatro execuções de scripts/trivy_vex.sh (com e sem VEX, mesma execução do banco) e
compara o conjunto suprimido (sem − com) com as declarações do VEX presentes no relatório sem
VEX. Grava results/p4_vex_trivy.csv, com o SHA-256 de cada relatório bruto.
"""

import csv
import hashlib
import json
from pathlib import Path

ETAPA = Path(__file__).resolve().parent.parent
SAIDA = Path.home() / ".cache/trivy-p4/out"
CASOS = (("webui", "teastore--image-webui", "descartesresearch/teastore-webui:1.4.2"),
         ("juice", "juice-shop--juice-shop-image", "bkimminich/juice-shop@sha256:547bd3fe..."))


def pares(arquivo):
    dados = json.loads(arquivo.read_text(encoding="utf-8"))
    achados, suprimidos = set(), set()
    for r in dados.get("Results") or []:
        for v in r.get("Vulnerabilities") or []:
            achados.add((v["VulnerabilityID"], (v.get("PkgIdentifier") or {}).get("PURL")))
        for m in r.get("ExperimentalModifiedFindings") or []:
            f = m.get("Finding") or {}
            suprimidos.add((f.get("VulnerabilityID"), (f.get("PkgIdentifier") or {}).get("PURL")))
    return achados, suprimidos


def sha(arquivo):
    return hashlib.sha256(arquivo.read_bytes()).hexdigest()


def main():
    linhas = []
    for nome, app, imagem in CASOS:
        sem, com = SAIDA / f"{nome}-sem.json", SAIDA / f"{nome}-com.json"
        a_sem, _ = pares(sem)
        a_com, listados = pares(com)
        vex = json.loads((ETAPA / f"pilotos/contexto-acoes/vex-{app}.json").read_text("utf-8"))
        declarados = {(s["vulnerability"]["name"], p["@id"])
                      for s in vex["statements"] for p in s["products"]}
        suprimidos, esperado = a_sem - a_com, declarados & a_sem
        linhas.append({
            "imagem": imagem, "achados_sem_vex": len(a_sem), "achados_com_vex": len(a_com),
            "suprimidos": len(suprimidos), "declarados_presentes": len(esperado),
            "declarados_ausentes_no_scan": len(declarados - a_sem),
            "listados_show_suppressed": len(listados),
            "s4_passa": int(suprimidos == esperado and listados == esperado),
            "sha256_sem": sha(sem), "sha256_com": sha(com)})
    destino = ETAPA / "results/p4_vex_trivy.csv"
    with destino.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0]))
        w.writeheader()
        w.writerows(linhas)
    for x in linhas:
        print(x)


if __name__ == "__main__":
    main()
