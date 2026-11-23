import sys
import unittest
from pathlib import Path

ETAPA = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ETAPA / "scripts"))

from comparar_politicas import (  # noqa: E402
    ALVOS, carregar, conferir_reproducao, domina, politicas,
)


class TesteComparacao(unittest.TestCase):
    def test_reproduz_numeros_publicados(self):
        # Falha (SystemExit) se P1/P2/P3 ou os limiares publicados divergirem.
        for app in ALVOS:
            us, _, _, universo = carregar(app)
            conferir_reproducao(app, us, universo)

    def test_p4_soma_um_bloqueio_por_confirmacao(self):
        for app in ALVOS:
            us, fila, confirmados, universo = carregar(app)
            res = politicas(us, fila, confirmados, universo)
            self.assertEqual(res["P4"]["bloqueios"], res["P3"]["bloqueios"] + len(confirmados))
            self.assertEqual(res["P4-teto"]["bloqueios"], res["P3"]["bloqueios"] + len(fila))

    def test_regra_de_dominancia(self):
        a = {"bloqueios": 10, "c": 5}
        self.assertTrue(domina(a, {"bloqueios": 12, "c": 5}, "c"))
        self.assertTrue(domina(a, {"bloqueios": 10, "c": 4}, "c"))
        self.assertFalse(domina(a, {"bloqueios": 10, "c": 5}, "c"))
        self.assertFalse(domina(a, {"bloqueios": 9, "c": 6}, "c"))


if __name__ == "__main__":
    unittest.main()
