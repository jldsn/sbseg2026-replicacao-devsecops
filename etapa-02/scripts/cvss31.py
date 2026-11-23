"""Nota base CVSS v3.1 a partir do vetor, conforme a especificação FIRST (seção 7)."""

import math

PESOS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}
PR = {"U": {"N": 0.85, "L": 0.62, "H": 0.27}, "C": {"N": 0.85, "L": 0.68, "H": 0.5}}
METRICAS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def roundup(valor):
    inteiro = round(valor * 100000)
    if inteiro % 10000 == 0:
        return inteiro / 100000.0
    return (math.floor(inteiro / 10000) + 1) / 10.0


def ler_vetor(vetor):
    partes = vetor.strip().split("/")
    if partes[0] != "CVSS:3.1":
        raise ValueError(f"Vetor deve começar com CVSS:3.1: {vetor}")
    campos = dict(p.split(":", 1) for p in partes[1:])
    if set(campos) != set(METRICAS):
        raise ValueError(f"Vetor base incompleto ou com métricas extras: {vetor}")
    return campos


def nota_base(vetor):
    m = ler_vetor(vetor)
    if m["S"] not in ("U", "C"):
        raise ValueError(f"Escopo inválido: {vetor}")
    iss = 1 - (1 - PESOS["C"][m["C"]]) * (1 - PESOS["I"][m["I"]]) * (1 - PESOS["A"][m["A"]])
    if m["S"] == "U":
        impacto = 6.42 * iss
    else:
        impacto = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    explor = 8.22 * PESOS["AV"][m["AV"]] * PESOS["AC"][m["AC"]] * PR[m["S"]][m["PR"]] * PESOS["UI"][m["UI"]]
    if impacto <= 0:
        return 0.0
    if m["S"] == "U":
        return roundup(min(impacto + explor, 10))
    return roundup(min(1.08 * (impacto + explor), 10))
