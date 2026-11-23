import json
import os
import sys
import unittest
from pathlib import Path

ETAPA = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ETAPA / "scripts"))

from politica_acoes import LIMIAR, Alvo, ler_contexto, nota  # noqa: E402

# A DVWA precisa dos relatórios do artefato dos autores (fora do repositório).
AUTORES = Path(os.environ.get("SBSEG_AUTORES", ETAPA.parent.parent
                              / "sbseg2026-deteccao-direta-indireta"))
APPS = ["teastore", "juice-shop"] + (["dvwa"] if (AUTORES / "data/raw").exists() else [])
PUBLICADOS = {"dvwa": (80, 56), "teastore": (262, 139), "juice-shop": (28, 9)}


class TesteAcoes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ctx = ler_contexto()
        cls.alvos = {app: Alvo(app, AUTORES, ctx) for app in APPS}
        cls.res = {app: {p: a.avaliar(p) for p in ("P2", "P3", "P3*", "ESCOPO", "P4")}
                   for app, a in cls.alvos.items()}

    def test_reproduz_unidades_publicadas(self):
        for app in APPS:
            r = self.res[app]
            self.assertEqual((len(r["P2"][0]), len(r["P3"][0])), PUBLICADOS[app], app)

    def test_p4_dentro_do_escopo(self):
        for app in APPS:
            r = self.res[app]
            self.assertLessEqual(r["P4"][2], r["ESCOPO"][2])
            self.assertLessEqual(set(r["P4"][1]), set(r["ESCOPO"][1]))

    def test_p4_nao_perde_caso_da_p3_estrela(self):
        for app in APPS:
            self.assertLessEqual(self.res[app]["P3*"][3], self.res[app]["P4"][3], app)

    def test_vex_e_exatamente_o_que_sai_do_bloqueio(self):
        for app in APPS:
            alvo = self.alvos[app]
            bloqueia = self.res[app]["P4"][2]
            for rel in {r["relatorio"] for r in alvo.registros}:
                arq = ETAPA / f"pilotos/contexto-acoes/vex-{app}--{Path(rel).stem}.json"
                vex = json.loads(arq.read_text("utf-8"))
                declarados = {(s["vulnerability"]["name"], p["@id"])
                              for s in vex["statements"] for p in s["products"]}
                for r in alvo.registros:
                    if r["relatorio"] != rel or nota(r["score"]) < LIMIAR or not r["purl"]:
                        continue
                    fora = (r["relatorio"], r["cve"]) not in bloqueia
                    self.assertEqual((r["cve"], r["purl"]) in declarados, fora, (app, r["ref"]))

    def test_carregado_inclui_a_definicao_registrada(self):
        for app in APPS:
            for r in self.alvos[app].registros:
                if r["carregado_registrado"] == "1":
                    self.assertEqual(r["carregado"], "1")


if __name__ == "__main__":
    unittest.main()
