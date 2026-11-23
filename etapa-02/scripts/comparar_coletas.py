"""Reprodutibilidade do coletor da P4 (docs/p4-acoes.md, seção Reprodutibilidade).

Compara, registro a registro, duas coletas do Trivy de imagem: a de referência
(results/contexto_imagem.csv) e uma segunda coleta feita com contêineres novos
(results/contexto_imagem_coleta2.csv). Pareia pela referência exata ao relatório
(aplicação, relatório, resultado, índice), não por (pacote, CVE), que é ambíguo quando o mesmo
par aparece em várias imagens.

Também compara a classificação final com a da versão anterior da P4
(results/contexto_execucao.csv, outra sessão, outros contêineres) para as unidades indiretas de
imagem. Das 268 unidades indiretas daquele arquivo, 2 são do Trivy FS, que a P4 atual não avalia.

Saída: results/p4_reprodutibilidade.csv.
"""

import csv
import json
from collections import Counter
from pathlib import Path

from analise_dvwa import gravar_csv
from politica_contexto import ALVOS, contexto

ETAPA = Path(__file__).resolve().parent.parent
COLUNAS = ("s1", "s2", "s3", "inicializacao", "carregado_registrado", "carregado")


def ler(nome):
    with (ETAPA / "results" / nome).open(encoding="utf-8", newline="") as f:
        return {(r["aplicacao"], r["relatorio"], r["resultado"], r["indice"]): r
                for r in csv.DictReader(f)}


def main():
    a, b = ler("contexto_imagem.csv"), ler("contexto_imagem_coleta2.csv")
    if set(a) != set(b):
        raise SystemExit("As duas coletas não têm os mesmos registros.")
    linhas = []
    for app in sorted({k[0] for k in a}):
        chaves = [k for k in a if k[0] == app]
        for col in COLUNAS:
            dif = [k for k in chaves if a[k][col] != b[k][col]]
            pacotes = Counter(a[k]["pacote"] for k in dif)
            linhas.append({"comparacao": "referencia_vs_coleta2_conteineres_novos", "aplicacao": app,
                           "coluna": col, "registros": len(chaves), "iguais": len(chaves) - len(dif),
                           "diferentes": len(dif),
                           "pacotes_diferentes": "|".join(sorted(pacotes))})
    # Versão anterior (contexto_execucao.csv): unidades indiretas de imagem.
    antigo = contexto()
    por_ref = {}
    for app, (arquivo, _, _) in ALVOS.items():
        for u in json.loads((ETAPA / arquivo).read_text(encoding="utf-8"))["unidades"]:
            por_ref[u["referencia"]] = u["id"]
    pares = Counter()
    for k, r in a.items():
        uid = por_ref.get(f"{r['relatorio']}#/Results/{r['resultado']}/Vulnerabilities/{r['indice']}")
        if uid in antigo:
            pares[(k[0], antigo[uid]["carregado_final"] == r["carregado"])] += 1
    for app in sorted({k for k, _ in pares}):
        iguais, dif = pares[(app, True)], pares[(app, False)]
        linhas.append({"comparacao": "versao_anterior_indiretos_de_imagem", "aplicacao": app,
                       "coluna": "carregado", "registros": iguais + dif, "iguais": iguais,
                       "diferentes": dif, "pacotes_diferentes": ""})
    fora = sum(1 for r in antigo.values()) - sum(pares.values())
    linhas.append({"comparacao": "versao_anterior_fora_do_escopo", "aplicacao": "todas",
                   "coluna": "", "registros": fora, "iguais": "", "diferentes": "",
                   "pacotes_diferentes": "unidades indiretas do Trivy FS, que a P4 atual não avalia"})
    gravar_csv(ETAPA / "results/p4_reprodutibilidade.csv", linhas)
    for x in linhas:
        print(x["comparacao"], x["aplicacao"], x["coluna"], x["iguais"], "/", x["registros"],
              x["pacotes_diferentes"][:80])


if __name__ == "__main__":
    main()
