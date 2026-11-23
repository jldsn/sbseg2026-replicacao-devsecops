"""Gera gráficos da análise secundária da DVWA a partir dos CSVs."""

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ETAPA = Path(__file__).resolve().parent.parent
FIGURAS = ETAPA / "figures"
CORES = {"P1": "#8D4913", "P2": "#1C6475", "P3": "#673D82",
         "uniforme": "#1C6475", "progressiva": "#673D82"}
ROTULOS = {"P1": "P1", "P2": "P2", "P3": "P3",
           "uniforme": "Uniforme", "progressiva": "Progressiva"}


def ler(nome):
    with (ETAPA / "results" / f"{nome}.csv").open(encoding="utf-8-sig") as arquivo:
        return list(csv.DictReader(arquivo))


def salvar(fig, nome):
    for formato in ("pdf", "png"):
        fig.savefig(FIGURAS / f"{nome}.{formato}", dpi=190, bbox_inches="tight")
    plt.close(fig)


def curvas(nome, dados, eixo_x, series, xlabel, titulo):
    fig, axs = plt.subplots(1, 2, figsize=(9.1, 3.55), layout="constrained")
    for politica in series:
        selecionadas = [r for r in dados if r["politica"] == politica]
        x = [float(r[eixo_x]) for r in selecionadas]
        for ax, chave in zip(axs, ["bloqueios", "cobertura_bloqueante"]):
            ax.step(x, [int(r[chave]) for r in selecionadas], "o-", where="post",
                    c=CORES[politica], label=ROTULOS[politica], lw=2, ms=5)
            ax.set_xticks(x, [f"{v:g}".replace(".", ",") for v in x])
            ax.set_xlabel(xlabel)
            ax.set_ylim(bottom=0)
            ax.grid(axis="y", alpha=.21)
            ax.spines[["right", "top"]].set_visible(False)
            ax.set_axisbelow(True)
    axs[0].set_ylabel("Unidades bloqueadas")
    axs[1].set_ylabel("Vulnerabilidades com bloqueio")
    axs[1].set_ylim(0, 13.65)
    axs[1].set_yticks([0, 3, 6, 9, 13])
    if eixo_x == "nota":
        for ax in axs:
            ax.axvline(7.5, lw=1, linestyle=":", color="#3B4D57")
    axs[0].legend(frameon=False)
    fig.suptitle(titulo, x=.03, ha="left", fontweight="bold")
    salvar(fig, nome)


def grade():
    linhas = ler("sensibilidade_combinada")
    medidas = {(float(r["nota_semgrep_error"]), int(r["limiar"]), r["politica"]):
               (int(r["bloqueios"]), int(r["cobertura_bloqueante"])) for r in linhas}
    notas = sorted({k[0] for k in medidas})
    limiares = sorted({k[1] for k in medidas})
    delta = np.array([[medidas[n, l, "uniforme"][1] - medidas[n, l, "progressiva"][1]
                     for l in limiares] for n in notas])
    fig, ax = plt.subplots(figsize=(6.5, 4.4), layout="constrained")
    img = ax.imshow(delta, cmap="Blues", vmin=0, vmax=int(delta.max()), aspect="auto")
    ax.set_xticks(range(len(limiares)), limiares)
    ax.set_yticks(range(len(notas)), [f"{n:g}".replace(".", ",") for n in notas])
    ax.set_xlabel("Limiar comum")
    ax.set_ylabel("Nota proxy do Semgrep ERROR")
    ax.set_title("Perda de cobertura da política progressiva na DVWA", loc="left", pad=12,
                 fontweight="bold")
    for i, row in enumerate(delta):
        for j, valor in enumerate(row):
            ax.text(j, i, str(valor), ha="center", va="center",
                    color="white" if valor > delta.max() / 2 else "#152D46")
    fig.colorbar(img, ax=ax, label="Vulnerabilidades a menos com bloqueio", shrink=.89)
    salvar(fig, "dvwa_grade_perda_cobertura")


def tornado():
    linhas = list(reversed(ler("sensibilidade_tornado")))
    base = 100 * float(linhas[0]["reducao_p3_vs_p2_base"])
    fig, ax = plt.subplots(figsize=(7.6, 3.6), layout="constrained")
    for i, r in enumerate(linhas):
        for lado, cor in (("baixa", "#1C6475"), ("alta", "#8D4913")):
            valor = 100 * float(r[f"reducao_{lado}"])
            ax.barh(i, valor - base, left=base, color=cor, height=.6,
                    label={"baixa": "Nota base − 2", "alta": "Nota base + 2"}[lado]
                    if i == 0 else None)
            if abs(valor - base) > .5:
                ax.text(valor + (1 if valor > base else -1), i,
                        f"{r[f'nota_{lado}'].replace('.', ',')} → {valor:.0f}%",
                        va="center", ha="left" if valor > base else "right", fontsize=8.5)
    ax.axvline(base, color="#3B4D57", lw=1, linestyle=":")
    ax.set_yticks(range(len(linhas)), [r["descricao"] for r in linhas], fontsize=8.5)
    ax.set_xlabel("Redução de bloqueios de P3 em relação a P2 (%)")
    ax.set_xlim(0, 100)
    ax.spines[["right", "top"]].set_visible(False)
    ax.legend(frameon=False, loc="lower right", fontsize=8.5)
    ax.set_title(f"Quanto cada nota proxy move a redução de {base:.0f}% do artigo",
                 loc="left", fontweight="bold")
    salvar(fig, "dvwa_tornado_proxies")


def distribuicao_monte_carlo():
    linhas = ler("sensibilidade_monte_carlo_distribuicao")
    rotulos = {"base_mais_menos_2": "Todas as notas em base ± 2",
               "amplo_1_a_10": "Todas as notas entre 1 e 10"}
    fig, axs = plt.subplots(1, 2, figsize=(9.1, 3.3), layout="constrained", sharey=True)
    for ax, (cenario, rotulo) in zip(axs, rotulos.items()):
        sel = [r for r in linhas if r["cenario"] == cenario]
        total = sum(int(r["amostras"]) for r in sel)
        ax.bar([int(r["reducao_pct"]) for r in sel],
               [100 * int(r["amostras"]) / total for r in sel], width=1, color="#673D82")
        ax.axvspan(25, 35, color="#90A0AA", alpha=.25, lw=0)
        ax.axvline(30, color="#3B4D57", lw=1, linestyle=":")
        ax.set_title(rotulo, loc="left", fontsize=10)
        ax.set_xlabel("Redução P3 vs P2 (%)")
        ax.set_xlim(0, 100)
        ax.spines[["right", "top"]].set_visible(False)
    axs[0].set_ylabel("Amostras (%)")
    fig.suptitle("Variação conjunta das notas proxy (10.000 sorteios por cenário)",
                 x=.03, ha="left", fontweight="bold")
    salvar(fig, "dvwa_monte_carlo_reducao")


def main():
    FIGURAS.mkdir(exist_ok=True)
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "text.color": "#152D46", "axes.labelcolor": "#152D46",
        "axes.edgecolor": "#90A0AA", "xtick.color": "#152D46", "ytick.color": "#152D46",
        "font.size": 10, "pdf.fonttype": 42,
    })
    curvas("dvwa_proxy_semgrep", ler("sensibilidade_semgrep_error"), "nota",
           ["P1", "P2", "P3"], "Nota atribuída aos alertas ERROR",
           "Sensibilidade à nota do Semgrep ERROR na DVWA")
    curvas("dvwa_limiares", ler("sensibilidade_limiares"), "limiar",
           ["uniforme", "progressiva"], "Limiar aplicado às duas regras",
           "Sensibilidade ao limiar na DVWA")
    grade()
    tornado()
    distribuicao_monte_carlo()


if __name__ == "__main__":
    main()
