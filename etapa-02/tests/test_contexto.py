import sys
import unittest
from pathlib import Path

ETAPA = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ETAPA / "scripts"))

from politica_contexto import ALVOS, avaliar, contexto  # noqa: E402


class TesteContexto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctx = contexto()
        cls.res = {app: avaliar(app, cls.ctx) for app in ALVOS}

    def test_p4_fica_entre_p3_estrela_e_p2_nos_indiretos(self):
        for app, (linhas, _) in self.res.items():
            pol = {x["politica"]: x for x in linhas}
            self.assertEqual(pol["P3*"]["indiretos_bloqueados"], 0)
            self.assertLessEqual(pol["P4"]["indiretos_bloqueados"],
                                 pol["P2"]["indiretos_bloqueados"])
            self.assertEqual(pol["P4"]["bloqueios"] - pol["P3*"]["bloqueios"],
                             pol["P4"]["indiretos_bloqueados"])

    def test_reproduz_p2_e_p3_publicados(self):
        esperado = {"dvwa": (80, 56), "teastore": (262, 139), "juice-shop": (28, 9)}
        for app, (linhas, _) in self.res.items():
            pol = {x["politica"]: x for x in linhas}
            self.assertEqual((pol["P2"]["bloqueios"], pol["P3"]["bloqueios"]), esperado[app])

    def test_contexto_cobre_todos_os_indiretos(self):
        for app, (_, resumo) in self.res.items():
            self.assertEqual(resumo["carregados"] + resumo["nao_carregados"],
                             resumo["indiretos_nota_7"])


if __name__ == "__main__":
    unittest.main()
