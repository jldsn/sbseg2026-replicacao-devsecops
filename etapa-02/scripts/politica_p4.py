"""Aplica P4 em modo de avaliação local às lacunas de bloqueio da DVWA.

Fila de confirmação dirigida (limiar 7), um item por ID da matriz sem bloqueio em P3:
  * apenas_indireta: o ID só tem sinais indiretos (critério original da Etapa 02);
  * perda_p2_p3: o ID é bloqueado em P2 e deixa de ser em P3, mesmo com sinal direto
    abaixo do limiar (caso de Exposed MySQL).
P4-A bloqueia no Deploy toda confirmação nova. P4-B exige também nota CVSS v3.1 do caso
confirmado >= 7, calculada a partir do vetor registrado no laudo. O vetor alternativo
mede a sensibilidade de P4-B à escolha do vetor.
"""

import argparse
import csv
import itertools
import json
import math
from dataclasses import dataclass
from pathlib import Path

from analise_dvwa import IDS_DVWA, Unidade, avaliar, gravar_csv, ler_json, sha256
from cvss31 import nota_base

STATUS = {"nao_executada", "inconclusiva", "nao_confirmada", "confirmada"}
LIMIAR = 7
VARIANTES = ("P4-A", "P4-B", "P4-B-alt")


@dataclass(frozen=True)
class Validacao:
    status: str = "nao_executada"
    evidencia: str = ""
    score_confirmacao: float | None = None
    configuracao: str = ""
    vetor: str = ""
    vetor_alternativo: str = ""
    score_alternativo: float | None = None


def ids_bloqueados(resultado):
    return set(filter(None, resultado["ids_bloqueados"].split("|")))


def selecionar_lacunas(unidades, bloqueadas, bloqueadas_p2=None):
    """Retorna {vid: (nome, sinais_indiretos, sinais_diretos, motivo)}."""
    if bloqueadas_p2 is None:
        bloqueadas_p2 = ids_bloqueados(avaliar(unidades, "P2", LIMIAR))
    alvos = {}
    for nome, vid in IDS_DVWA.items():
        if vid in bloqueadas:
            continue
        indiretos = [u.id for u in unidades if u.vinculos.get(vid) == "indireta"]
        diretos = [u.id for u in unidades if u.vinculos.get(vid) == "direta"]
        if indiretos and not diretos:
            motivo = "apenas_indireta"
        elif vid in bloqueadas_p2:
            motivo = "perda_p2_p3"
        else:
            continue
        alvos[vid] = (nome, indiretos, diretos, motivo)
    return alvos


def nota_do_vetor(vid, vetor, score_informado=None):
    if not vetor:
        return score_informado
    nota = nota_base(vetor)
    if score_informado is not None and not math.isclose(score_informado, nota):
        raise ValueError(f"{vid}: score {score_informado} diverge do vetor ({nota}).")
    return nota


def ler_validacoes(caminho, alvos):
    if caminho is None:
        return {}
    dados = {}
    with caminho.open(encoding="utf-8-sig", newline="") as arquivo:
        for row in csv.DictReader(arquivo):
            vid, status = row["vulnerability_id"], row["status"]
            if vid not in alvos or vid in dados or status not in STATUS:
                raise ValueError(f"Linha inválida em {caminho.name} para {vid}: {status}")
            evidencia = row["evidencia"]
            configuracao = row["configuracao"]
            if status != "nao_executada":
                if not evidencia or not configuracao:
                    raise ValueError(f"{vid}: registre a evidência e a configuração do teste.")
                caminho_evidencia = caminho.parent / evidencia
                if sha256(caminho_evidencia) != row["sha256_evidencia"]:
                    raise ValueError(f"{vid}: SHA-256 da evidência diverge.")
            score = float(row["score_confirmacao"]) if row.get("score_confirmacao") else None
            if score is not None and (not math.isfinite(score) or not 0 <= score <= 10):
                raise ValueError(f"{vid}: use uma nota entre 0 e 10.")
            vetor = (row.get("vetor_cvss_confirmacao") or "").strip()
            vetor_alt = (row.get("vetor_cvss_alternativo") or "").strip()
            dados[vid] = Validacao(
                status, evidencia, nota_do_vetor(vid, vetor, score), configuracao,
                vetor, vetor_alt, nota_do_vetor(vid, vetor_alt),
            )
    return dados


def bloqueia_confirmacao(validacao, politica, limiar=LIMIAR):
    if politica not in VARIANTES:
        raise ValueError(f"Variante P4 desconhecida: {politica}")
    if validacao.status != "confirmada":
        return False
    if politica == "P4-A":
        return True
    score = validacao.score_confirmacao if politica == "P4-B" else validacao.score_alternativo
    return score is not None and score >= limiar


def executar(base, raiz, laudos):
    unidades = [Unidade(**u) for u in ler_json(base)["unidades"]]
    p3 = avaliar(unidades, "P3", LIMIAR)
    p2 = avaliar(unidades, "P2", LIMIAR)
    bloqueadas = ids_bloqueados(p3)
    alvos = selecionar_lacunas(unidades, bloqueadas, ids_bloqueados(p2))
    validacoes = ler_validacoes(laudos, alvos)
    fila = []
    for vid, (nome, indiretos, diretos, motivo) in alvos.items():
        v = validacoes.get(vid, Validacao())
        fila.append({
            "vulnerability_id": vid, "nome": nome, "motivo": motivo,
            "sinais_indiretos": len(indiretos), "sinais_diretos": len(diretos),
            "finding_ids": "|".join(indiretos + diretos), "status": v.status,
            "evidencia": v.evidencia, "configuracao": v.configuracao,
            "vetor_cvss_confirmacao": v.vetor, "score_confirmacao": v.score_confirmacao,
            "vetor_cvss_alternativo": v.vetor_alternativo, "score_alternativo": v.score_alternativo,
            "adiciona_bloqueio_p4_a": int(bloqueia_confirmacao(v, "P4-A")),
            "adiciona_bloqueio_p4_b": int(bloqueia_confirmacao(v, "P4-B")),
            "adiciona_bloqueio_p4_b_alt": int(bloqueia_confirmacao(v, "P4-B-alt")),
        })
    resultados = []
    for p, campo in [("P3", ""), ("P4-A", "adiciona_bloqueio_p4_a"),
                     ("P4-B", "adiciona_bloqueio_p4_b"),
                     ("P4-B-alt", "adiciona_bloqueio_p4_b_alt")]:
        novas = {r["vulnerability_id"] for r in fila if campo and r[campo]}
        resultados.append({
            "politica": p,
            "base_bloqueios": p3["bloqueios"], "bloqueios_adicionais_no_deploy": len(novas),
            "decisoes_simuladas": p3["bloqueios"] + len(novas),
            "cobertura_bloqueante": len(bloqueadas | novas),
            "vulnerabilidades_matriz": len(IDS_DVWA), "novos_ids_bloqueados": "|".join(sorted(novas)),
            "referencia_p2_bloqueios": p2["bloqueios"],
            "referencia_p2_cobertura": p2["cobertura_bloqueante"],
            "fonte_validacoes": (
                "nao_aplicavel" if p == "P3"
                else "evidencias_informadas" if laudos else "sem_laudos"
            ),
        })
    condicionais = []
    for n in range(len(alvos) + 1):
        for combinacao in itertools.combinations(alvos, n):
            condicionais.append({
                "natureza": "condicional_p4_a", "hipotese_ids_confirmados": "|".join(combinacao),
                "confirmacoes": n, "decisoes_simuladas": p3["bloqueios"] + n,
                "cobertura_bloqueante": len(bloqueadas) + n,
                "vulnerabilidades_matriz": len(IDS_DVWA),
            })
    gravar_csv(raiz / "p4_fila.csv", fila)
    gravar_csv(raiz / "p4_resultados.csv", resultados)
    gravar_csv(raiz / "p4_cenarios_condicionais.csv", condicionais)
    print(json.dumps(resultados, ensure_ascii=False, indent=2))


def main():
    etapa = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=etapa / "data/normalized/dvwa.json")
    parser.add_argument("--out", type=Path, default=etapa / "results")
    parser.add_argument("--validacoes", type=Path, help="CSV com laudos da configuração avaliada")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    executar(args.base, args.out, args.validacoes)


if __name__ == "__main__":
    main()
