"""P4 orientada a ações, com contexto de execução (protocolo em docs/p4-acoes.md).

Pergunta: o que o time precisa fazer para liberar o deploy? Cada política é avaliada em ações de
correção (definição única, seção 4 do protocolo) e não só em unidades bloqueadas.

Políticas: P2, P3, P3*, A2 (artigo e alternativa de limiar); ESCOPO (ablação: todos os registros
do Trivy de imagem com nota >= 7, sem coletor); P4 (ESCOPO filtrado pelo coletor, por CVE).
Entradas: unidades normalizadas, relatórios do Trivy de imagem, results/contexto_imagem.csv
(scripts/contexto_execucao.py --imagem) e a fila de confirmações da P3*.
Saídas: results/p4_acoes.csv, results/p4_acoes_resumo.csv e pilotos/contexto-acoes/vex-<alvo>--<imagem>.json.
"""

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path

from analise_dvwa import gravar_csv, ler_json
from politica_contexto import ALVOS as ALVOS_CTX
from politica_contexto import confirmados
from resumir_pilotos import score_trivy

ETAPA = Path(__file__).resolve().parent.parent
LIMIAR = 7.0
IMAGEM = {"Trivy Image", "Trivy Container"}
ECOSSISTEMA = {"jar": "maven", "pom": "maven", "node-pkg": "npm", "npm": "npm",
               "gobinary": "go", "gomod": "go"}
POLITICAS = ("P1", "P2", "P3", "P3*", "A2", "ESCOPO", "P4-reg", "P4")
TIMESTAMP_VEX = "2026-11-22T00:00:00Z"


def nota(x):
    return x or 0.0


class Alvo:
    """Junta unidades normalizadas, registros do Trivy de imagem e o contexto de execução."""

    def __init__(self, app, autores, contexto):
        self.app = app
        self.autores = autores
        arquivo, self.universo, fila = ALVOS_CTX[app]
        self.unidades = ler_json(ETAPA / arquivo)["unidades"]
        self.confirmados = confirmados(app, fila)
        self.registros = [r for r in contexto if r["aplicacao"] == app]
        self._relatorios = {}
        por_ref = {u["referencia"]: u for u in self.unidades if u["ferramenta"] in IMAGEM
                   and not u["granularidade"].startswith("aggregate_")}
        for r in self.registros:
            v = self.vuln(r)
            r["score"] = score_trivy(v)
            r["ref"] = f"{r['relatorio']}#/Results/{r['resultado']}/Vulnerabilities/{r['indice']}"
            r["unidade"] = por_ref.get(r["ref"])
            r["fixavel"] = bool(r["versao_corrigida"])
        faltando = set(por_ref) - {r["ref"] for r in self.registros}
        if faltando:
            raise SystemExit(f"{app}: unidades de imagem sem registro: {sorted(faltando)[:3]}")
        # Conferência: a nota de cada unidade individual é a nota do seu registro.
        for r in self.registros:
            if r["unidade"] and nota(r["unidade"]["score"]) != nota(r["score"]):
                raise SystemExit(f"{app}: nota diverge em {r['ref']}")
        self.agregados = [u for u in self.unidades if u["granularidade"].startswith("aggregate_")]
        self.fixable_vinculos = {}
        for u in self.agregados:
            if u["granularidade"] == "aggregate_fixable":
                self.fixable_vinculos[self.relatorio_do_agregado(u)] = u["vinculos"]

    def relatorio(self, caminho):
        if caminho not in self._relatorios:
            base = (self.autores / "data/raw" / caminho if caminho.startswith("reports-")
                    else ETAPA / caminho)
            self._relatorios[caminho] = json.loads(base.read_text(encoding="utf-8"))
        return self._relatorios[caminho]

    def vuln(self, r):
        res = self.relatorio(r["relatorio"])["Results"][int(r["resultado"])]
        return res["Vulnerabilities"][int(r["indice"])]

    def relatorio_do_agregado(self, u):
        if self.app == "dvwa":
            return self.registros[0]["relatorio"]
        return u["referencia"].split("#")[0]

    def membros(self, u):
        """Registros que compõem um agregado, pela mesma regra de analise_alvos/analise_dvwa."""
        rel = self.relatorio_do_agregado(u)
        rs = [r for r in self.registros if r["relatorio"] == rel]
        g = u["granularidade"]
        if g == "aggregate_eosl":
            return rs
        if g == "aggregate_fixable":
            return [r for r in rs if r["fixavel"]]
        return [r for r in rs if r["unidade"] is None]  # aggregate_outras / aggregate_other

    def base_do_agregado(self, u):
        rel = self.relatorio_do_agregado(u)
        return next(r["imagem_base"] for r in self.registros if r["relatorio"] == rel)

    # --- ações ---------------------------------------------------------------------------

    def acao_registro(self, r):
        if r["tipo_pacote"] in ("debian", "ubuntu"):
            return ("pacote_so", r["imagem_base"], r["pacote_fonte"])
        return ("dependencia", ECOSSISTEMA.get(r["tipo_pacote"], r["tipo_pacote"]), r["pacote"])

    def acao_unidade(self, u):
        f = u["ferramenta"]
        if f == "Semgrep":
            caminho, _, ponteiro = u["referencia"].partition("#")
            dados = self.relatorio(caminho) if caminho.startswith("reports-") else \
                ler_json_cache(ETAPA / caminho)
            achado = dados["results"][int(ponteiro.rsplit("/", 1)[1])]
            return ("semgrep", u["identificador_scanner"], achado["path"])
        if f == "Trivy FS (SCA)":
            caminho, _, ponteiro = u["referencia"].partition("#")
            dados = self.relatorio(caminho) if caminho.startswith("reports-") else \
                ler_json_cache(ETAPA / caminho)
            p = ponteiro.strip("/").split("/")
            res = dados["Results"][int(p[1])]
            v = res["Vulnerabilities"][int(p[3])]
            return ("dependencia", ECOSSISTEMA.get(res.get("Type"), res.get("Type")), v["PkgName"])
        return ("unidade", f, u["id"])

    # --- políticas -----------------------------------------------------------------------

    def cve_carregado(self, campo="carregado"):
        """(relatório, CVE) -> algum pacote afetado está carregado nessa imagem.
        campo="carregado_registrado" usa a definição registrada, sem a correção pós-registro."""
        d = defaultdict(bool)
        for r in self.registros:
            d[(r["relatorio"], r["cve"])] |= r[campo] == "1"
        return d

    def avaliar(self, politica):
        """Devolve (itens bloqueados, ações) para a política."""
        nao_imagem = [u for u in self.unidades if u["ferramenta"] not in IMAGEM]
        imagem_ind = [u for u in self.unidades if u["ferramenta"] in IMAGEM
                      and not u["granularidade"].startswith("aggregate_")]
        itens = []  # (tipo, objeto, vinculos)
        # P1 (artigo): limiar 9 em todas as classes; as demais usam o limiar 7.
        LIMIAR = 9.0 if politica == "P1" else globals()["LIMIAR"]
        base_p3 = [u for u in nao_imagem if nota(u["score"]) >= LIMIAR and u["classe"] != "indireta"]
        if politica in ("P1", "P2"):
            app_units = [u for u in nao_imagem if nota(u["score"]) >= LIMIAR]
        else:
            app_units = base_p3
        itens += [("unidade", u, u["vinculos"]) for u in app_units]
        if politica in ("P3*", "ESCOPO", "P4-reg", "P4"):
            itens += [("confirmacao", vid, {vid: "direta"}) for vid in sorted(self.confirmados)]
        if politica in ("P1", "P2", "P3", "P3*", "A2"):
            # Modelo do artigo: unidades individuais (indiretas) e agregados por máximo.
            for u in imagem_ind:
                if nota(u["score"]) < LIMIAR:
                    continue
                if politica in ("P1", "P2") or (politica == "A2" and nota(u["score"]) >= 9):
                    itens.append(("registro_unidade", u, u["vinculos"]))
            for u in self.agregados:
                if nota(u["score"]) >= LIMIAR:
                    itens.append(("agregado", u, u["vinculos"]))
        else:
            # ESCOPO e P4: todo registro de imagem, sem a classe direta/indireta.
            carregado = self.cve_carregado(
                "carregado_registrado" if politica == "P4-reg" else "carregado")
            for u in self.agregados:
                if u["granularidade"] == "aggregate_eosl" and nota(u["score"]) >= LIMIAR:
                    itens.append(("agregado", u, u["vinculos"]))
            for r in self.registros:
                if nota(r["score"]) < LIMIAR:
                    continue
                if politica.startswith("P4") and not carregado[(r["relatorio"], r["cve"])]:
                    continue
                vinc = dict(r["unidade"]["vinculos"]) if r["unidade"] else {}
                if r["fixavel"]:
                    vinc.update(self.fixable_vinculos.get(r["relatorio"], {}))
                itens.append(("registro", r, vinc))
        acoes = defaultdict(lambda: {"itens": 0, "cves": set(), "sem_correcao": False,
                                     "versoes": set()})

        def registrar(chave, r=None):
            a = acoes[chave]
            a["itens"] += 1
            if r is not None:
                a["cves"].add(r["cve"])
                if r["versao_corrigida"]:
                    a["versoes"].add(r["versao_corrigida"])
                else:
                    a["sem_correcao"] = True

        cves_imagem = set()
        for tipo, obj, _ in itens:
            if tipo == "unidade":
                registrar(self.acao_unidade(obj))
            elif tipo == "confirmacao":
                registrar(("confirmacao", "P3*", obj))
            elif tipo == "registro":
                registrar(self.acao_registro(obj), obj)
                cves_imagem.add((obj["relatorio"], obj["cve"]))
            elif tipo == "registro_unidade":
                r = next(x for x in self.registros if x["unidade"] is obj)
                registrar(self.acao_registro(r), r)
                cves_imagem.add((r["relatorio"], r["cve"]))
            elif tipo == "agregado":
                if obj["granularidade"] == "aggregate_eosl":
                    registrar(("migrar_so", self.base_do_agregado(obj), ""))
                else:
                    for r in self.membros(obj):
                        if nota(r["score"]) >= LIMIAR:
                            registrar(self.acao_registro(r), r)
                            cves_imagem.add((r["relatorio"], r["cve"]))
        ids = {vid for _, _, v in itens for vid in v}
        return itens, acoes, cves_imagem, ids

    def vex(self, relatorio, campo="carregado"):
        """Declarações OpenVEX, para uma imagem, dos CVEs (nota >= 7) que a P4 tira do bloqueio.
        Uma declaração por imagem: o mesmo PURL pode estar carregado em um serviço e não em outro."""
        carregado = self.cve_carregado(campo)
        produtos = defaultdict(set)
        for r in self.registros:
            if r["relatorio"] == relatorio and nota(r["score"]) >= LIMIAR \
                    and not carregado[(r["relatorio"], r["cve"])] and r["purl"]:
                produtos[r["cve"]].add(r["purl"])
        nome = Path(relatorio).stem
        return {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "@id": f"https://github.com/jldsn/sbseg2026-replicacao-devsecops/vex/{self.app}/{nome}",
            "author": "Etapa 02 (replicação SBSeg 2026), coletor de contexto de execução",
            "timestamp": TIMESTAMP_VEX, "version": 1,
            "statements": [{
                "vulnerability": {"name": cve},
                "products": [{"@id": p} for p in sorted(ps)],
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "impact_statement": "Nenhum processo da implantação de referência carregou o "
                                    "pacote (S1-S3, inicialização; ver docs/p4-acoes.md). "
                                    "Reavaliar pelo Runtime Watch.",
            } for cve, ps in sorted(produtos.items())],
        }


_CACHE = {}


def ler_json_cache(caminho):
    if caminho not in _CACHE:
        _CACHE[caminho] = ler_json(caminho)
    return _CACHE[caminho]


def ler_contexto():
    with (ETAPA / "results/contexto_imagem.csv").open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def avaliar_alvo(alvo):
    detalhe, resumo = [], []
    for pol in POLITICAS:
        itens, acoes, cves, ids = alvo.avaliar(pol)
        tipos = Counter(k[0] for k in acoes)
        # Atualizar pacote de SO numa imagem base que a própria lista manda migrar não é
        # trabalho separado: a migração absorve essas ações.
        migrar = {k[1] for k in acoes if k[0] == "migrar_so"}
        absorvidas = sum(1 for k in acoes if k[0] == "pacote_so" and k[1] in migrar)
        resumo.append({
            "aplicacao": alvo.app, "politica": pol, "universo": alvo.universo,
            "unidades_bloqueadas": len(itens), "acoes": len(acoes),
            "acoes_migrar_so": tipos["migrar_so"], "acoes_pacote_so": tipos["pacote_so"],
            "acoes_dependencia": tipos["dependencia"], "acoes_semgrep": tipos["semgrep"],
            "acoes_outras": tipos["unidade"] + tipos["confirmacao"],
            "acoes_absorvidas_pela_migracao": absorvidas,
            "acoes_nao_absorvidas": len(acoes) - absorvidas,
            "cves_imagem_bloqueantes": len(cves),
            "cves_imagem_distintos": len({c for _, c in cves}),
            "cobertura": len(ids), "ids": "|".join(sorted(ids))})
        for chave, a in sorted(acoes.items()):
            detalhe.append({"aplicacao": alvo.app, "politica": pol, "tipo": chave[0],
                            "contexto": chave[1], "alvo_da_acao": chave[2], "itens": a["itens"],
                            "cves": len(a["cves"]), "sem_correcao": int(a["sem_correcao"]),
                            "versoes_corrigidas": "|".join(sorted(a["versoes"]))[:300]})
    return detalhe, resumo


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--autores", type=Path, required=True,
                   help="Clone do artefato dos autores (relatórios da DVWA)")
    a = p.parse_args()
    ctx = ler_contexto()
    detalhe, resumo = [], []
    destino_vex = ETAPA / "pilotos/contexto-acoes"
    destino_vex.mkdir(parents=True, exist_ok=True)
    for app in ALVOS_CTX:
        alvo = Alvo(app, a.autores, ctx)
        d, r = avaliar_alvo(alvo)
        detalhe += d
        resumo += r
        for relatorio in sorted({r["relatorio"] for r in alvo.registros}):
            nome = Path(relatorio).stem
            (destino_vex / f"vex-{app}--{nome}.json").write_text(
                json.dumps(alvo.vex(relatorio), indent=1, ensure_ascii=False) + "\n",
                encoding="utf-8")
            # Definição registrada, antes das correções pós-registro (para a verificação S5).
            (destino_vex / f"vex-{app}--{nome}-registrado.json").write_text(
                json.dumps(alvo.vex(relatorio, "carregado_registrado"), indent=1,
                           ensure_ascii=False) + "\n", encoding="utf-8")
    gravar_csv(ETAPA / "results/p4_acoes.csv", detalhe)
    gravar_csv(ETAPA / "results/p4_acoes_resumo.csv", resumo)
    for x in resumo:
        print(f"{x['aplicacao']:10} {x['politica']:6} unidades {x['unidades_bloqueadas']:>4} · "
              f"ações {x['acoes']:>3} (SO {x['acoes_migrar_so']}, pacote {x['acoes_pacote_so']}, "
              f"dep {x['acoes_dependencia']}, semgrep {x['acoes_semgrep']}, outras "
              f"{x['acoes_outras']}; não absorvidas {x['acoes_nao_absorvidas']}) · "
              f"CVEs imagem {x['cves_imagem_distintos']} · "
              f"{x['cobertura']}/{x['universo']}")


if __name__ == "__main__":
    main()
