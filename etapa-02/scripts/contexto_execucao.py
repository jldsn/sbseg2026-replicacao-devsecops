"""Coletor de contexto de execução da P4 (protocolo em docs/p4-contexto.md).

Para cada alvo em execução local, registra o que os processos da aplicação carregaram:
bibliotecas mapeadas em memória, arquivos abertos, linhas de comando e, no Node.js, os
módulos já carregados (hook em ambientes/contexto/hook-modulos.js). Depois decide, para cada
achado indireto do Trivy, se o pacote vulnerável está "em uso" ou "latente".

Duas observações: S1 logo após a aplicação responder e S2 depois de tráfego benigno (GET em
páginas públicas, sem payload). A leitura de /proc é feita por um contêiner auxiliar que
compartilha o espaço de processos do alvo, porque a imagem do Juice Shop não tem shell.
"""

import argparse
import csv
import io
import json
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

ETAPA = Path(__file__).resolve().parent.parent
AUXILIAR = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
TEASTORE = ("registry", "db", "persistence", "auth", "image", "recommender", "webui")

ALVOS = {
    "dvwa": {
        "unidades": "data/normalized/dvwa.json",
        "containers": ["dvwa-r"],
        "trafego": ["http://127.0.0.1:18083/login.php", "http://127.0.0.1:18083/setup.php",
                    "http://127.0.0.1:18083/index.php", "http://127.0.0.1:18083/about.php"],
    },
    "teastore": {
        "unidades": "data/normalized/alvo-teastore.json",
        "containers": [f"teastore-{s}-1" for s in TEASTORE],
        "trafego": [f"http://127.0.0.1:18081/tools.descartes.teastore.webui/{p}" for p in
                    ("", "login", "category?category=2&page=1", "product?id=7", "cart",
                     "about", "status", "category?category=3&page=2")],
    },
    "juice-shop": {
        "unidades": "data/normalized/alvo-juice-shop.json",
        "containers": ["juice-r"],
        "trafego": [f"http://127.0.0.1:18082/{p}" for p in
                    ("", "rest/products/search?q=apple", "api/Products", "rest/languages",
                     "api/Challenges", "rest/admin/application-version", "ftp", "metrics")],
    },
}

SCRIPT_PROC = r"""
for p in /proc/[0-9]*; do
  [ -r $p/maps ] || continue
  awk '{print "MAP " $6}' $p/maps 2>/dev/null
  for f in $p/fd/*; do echo "FD $(readlink $f 2>/dev/null)"; done
  echo "CMD $(tr '\0' ' ' < $p/cmdline 2>/dev/null)"
done
"""


def observar(container):
    saida = subprocess.run(
        ["docker", "run", "--rm", f"--pid=container:{container}", "--cap-add", "SYS_PTRACE",
         AUXILIAR, "sh", "-c", SCRIPT_PROC], capture_output=True, text=True, check=True).stdout
    caminhos, comandos = set(), []
    for linha in saida.splitlines():
        tipo, _, valor = linha.partition(" ")
        if tipo in ("MAP", "FD") and valor.startswith("/"):
            caminhos.add(valor.removesuffix(" (deleted)"))
        elif tipo == "CMD" and valor.strip():
            comandos.append(valor.strip())
    modulos = set()
    tar = subprocess.run(["docker", "cp", f"{container}:/tmp/p4-modulos.txt", "-"],
                         capture_output=True)
    if tar.returncode == 0:
        with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as t:
            for m in t.getmembers():
                modulos |= set(t.extractfile(m).read().decode().split())
    return {"caminhos": caminhos, "comandos": comandos, "modulos": modulos}


def dpkg(container):
    """Mapa arquivo -> pacote a partir das listas do dpkg do próprio contêiner.

    Imagens distroless não têm /var/lib/dpkg/info; a lista de arquivos de cada pacote fica em
    /var/lib/dpkg/status.d/<pacote>.md5sums ("hash  caminho"). Sem ler esse formato, nenhum
    pacote de SO do Juice Shop aparecia carregado (bug achado na revisão de 22/11/2026)."""
    mapa = {}
    tar = subprocess.run(["docker", "cp", f"{container}:/var/lib/dpkg/info", "-"],
                         capture_output=True)
    if tar.returncode == 0:
        with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as t:
            for m in t.getmembers():
                if m.isfile() and m.name.endswith(".list"):
                    pacote = PurePosixPath(m.name).stem.split(":")[0]
                    for linha in t.extractfile(m).read().decode("utf-8", "replace").splitlines():
                        mapa.setdefault(linha.strip(), set()).add(pacote)
    tar = subprocess.run(["docker", "cp", f"{container}:/var/lib/dpkg/status.d", "-"],
                         capture_output=True)
    if tar.returncode == 0:
        with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as t:
            for m in t.getmembers():
                if m.isfile() and m.name.endswith(".md5sums"):
                    pacote = PurePosixPath(m.name).name.removesuffix(".md5sums").split(":")[0]
                    for linha in t.extractfile(m).read().decode("utf-8", "replace").splitlines():
                        partes = linha.split(None, 1)
                        if len(partes) == 2:
                            mapa.setdefault("/" + partes[1].strip().lstrip("/"), set()).add(pacote)
    return mapa


def pacotes_carregados(obs, mapa):
    pacotes = set()
    for c in obs["caminhos"]:
        for alt in {c, c.replace("/usr/lib/", "/lib/", 1), c.replace("/lib/", "/usr/lib/", 1)}:
            pacotes |= mapa.get(alt, set())
    return pacotes


def scripts_de_inicializacao(container):
    """Texto do Entrypoint/Cmd da imagem e dos scripts que eles chamam (processos de vida
    curta que o snapshot não vê, como o gosu no banco do TeaStore)."""
    cfg = json.loads(subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config}}", container],
        capture_output=True, text=True, check=True).stdout)
    texto = " ".join((cfg.get("Entrypoint") or []) + (cfg.get("Cmd") or []))
    candidatos = {t.strip(";&'\"") for t in texto.split() if t.endswith(".sh") or "/" in t}
    for nome in list(candidatos):
        caminhos = [nome] if nome.startswith("/") else [f"/usr/local/bin/{nome}", f"/{nome}"]
        for caminho in caminhos:
            r = subprocess.run(["docker", "cp", f"{container}:{caminho}", "-"], capture_output=True)
            if r.returncode == 0:
                with tarfile.open(fileobj=io.BytesIO(r.stdout)) as t:
                    for m in t.getmembers():
                        if m.isfile() and m.size < 2_000_000:
                            texto += "\n" + t.extractfile(m).read().decode("utf-8", "replace")
                break
    return set(texto.replace("(", " ").replace(")", " ").replace(";", " ").split())


def zap_spider(urls):
    """Tráfego benigno mais amplo: spider passivo do ZAP que já roda no compose do TeaStore."""
    api = "http://127.0.0.1:18090/JSON"
    for url in urls:
        q = urllib.parse.urlencode({"apikey": "piloto-loopback", "url": url, "recurse": "true"})
        try:
            sid = json.load(HTTP.open(f"{api}/spider/action/scan/?{q}", timeout=30))["scan"]
            prazo = time.monotonic() + 150
            while time.monotonic() < prazo:
                st = json.load(HTTP.open(f"{api}/spider/view/status/?apikey=piloto-loopback"
                                         f"&scanId={sid}", timeout=30))["status"]
                if st == "100":
                    break
                time.sleep(3)
        except Exception:  # noqa: BLE001
            pass


def trafegar(urls):
    for url in urls:
        try:
            with HTTP.open(url, timeout=30) as r:
                r.read()
        except Exception:  # noqa: BLE001 - tráfego é só para exercitar rotas públicas
            pass


def resolver(ref, autores):
    caminho, _, ponteiro = ref.partition("#")
    base = autores / "data/raw" / caminho if caminho.startswith("reports-") else ETAPA / caminho
    dados = json.loads(base.read_text(encoding="utf-8"))
    partes = ponteiro.strip("/").split("/")
    resultado = dados["Results"][int(partes[1])]
    return caminho, resultado, resultado["Vulnerabilities"][int(partes[3])]


def container_do_relatorio(app, caminho):
    if app == "teastore":
        nome = PurePosixPath(caminho).name
        if nome.startswith("image-"):
            return [f"teastore-{nome[6:-5]}-1"]
        return ALVOS["teastore"]["containers"]  # Trivy FS: dependência de qualquer serviço
    return ALVOS[app]["containers"]


def executado_na_inicializacao(resultado, vuln, containers, init, mapas):
    tipo, nome = resultado.get("Type"), vuln["PkgName"]
    if tipo == "gobinary":
        alvo = PurePosixPath(resultado["Target"]).name
        return any(alvo in init[c] for c in containers)
    if tipo in ("debian", "ubuntu"):
        for c in containers:
            comandos = {PurePosixPath(p).name for p, pk in mapas[c].items() if nome in pk
                        and PurePosixPath(p).parent.name in ("bin", "sbin")}
            if comandos & init[c]:
                return True
    return False


def em_uso(resultado, vuln, containers, obs, pacotes):
    tipo = resultado.get("Type")
    nome = vuln["PkgName"]
    if tipo in ("debian", "ubuntu"):
        if any(nome in pacotes[c] for c in containers):
            return True
        if nome == "libc6":  # imagem distroless sem listas do dpkg
            return any("libc.so" in p or "libc-" in p for c in containers
                       for p in obs[c]["caminhos"])
        return False
    if tipo == "jar":
        jar = PurePosixPath(vuln.get("PkgPath", "")).name
        return any(PurePosixPath(p).name == jar for c in containers for p in obs[c]["caminhos"])
    if tipo == "pom":
        artefato = nome.split(":")[-1] + "-"
        return any(PurePosixPath(p).name.startswith(artefato) and p.endswith(".jar")
                   for c in containers for p in obs[c]["caminhos"])
    if tipo == "gobinary":
        alvo = "/" + resultado["Target"].lstrip("/")
        return any(alvo in cmd.split() for c in containers for cmd in obs[c]["comandos"])
    if tipo == "node-pkg":
        pasta = "/" + str(PurePosixPath(vuln.get("PkgPath", "")).parent) + "/"
        return any(pasta in m for c in containers for m in obs[c]["modulos"])
    raise ValueError(f"Tipo de pacote sem regra: {tipo}")


def observar_alvo(app, saida_bruta, spider):
    """S1, tráfego benigno, S2, spider passivo, S3; grava as observações brutas."""
    cfg = ALVOS[app]
    mapas = {c: dpkg(c) for c in cfg["containers"]}
    init = {c: scripts_de_inicializacao(c) for c in cfg["containers"]}
    s1 = {c: observar(c) for c in cfg["containers"]}
    trafegar(cfg["trafego"])
    time.sleep(8)
    s2 = {c: observar(c) for c in cfg["containers"]}
    # S3 (pós-registro): spider passivo do ZAP com os endereços vistos de dentro da rede.
    zap_spider(spider.get(app, []))
    time.sleep(8)
    s3 = {c: observar(c) for c in cfg["containers"]}
    for c in cfg["containers"]:
        for rotulo, obs in (("s1", s1[c]), ("s2", s2[c]), ("s3", s3[c])):
            (saida_bruta / f"{app}--{c}--{rotulo}.txt").write_text(
                "\n".join(sorted(obs["caminhos"]) + ["# comandos"] + obs["comandos"]
                          + ["# modulos"] + sorted(obs["modulos"])) + "\n", encoding="utf-8")
    return mapas, init, s1, s2, s3


def coletar(app, autores, saida_bruta, spider):
    cfg = ALVOS[app]
    mapas, init, s1, s2, s3 = observar_alvo(app, saida_bruta, spider)
    pac1 = {c: pacotes_carregados(s1[c], mapas[c]) for c in cfg["containers"]}
    pac2 = {c: pacotes_carregados(s2[c], mapas[c]) for c in cfg["containers"]}
    pac3 = {c: pacotes_carregados(s3[c], mapas[c]) for c in cfg["containers"]}
    unidades = json.loads((ETAPA / cfg["unidades"]).read_text(encoding="utf-8"))["unidades"]
    linhas = []
    for u in unidades:
        if u["classe"] != "indireta":
            continue
        caminho, resultado, vuln = resolver(u["referencia"], autores)
        cs = container_do_relatorio(app, caminho)
        a = em_uso(resultado, vuln, cs, s1, pac1)
        b = em_uso(resultado, vuln, cs, s2, pac2)
        c3 = em_uso(resultado, vuln, cs, s3, pac3)
        ini = executado_na_inicializacao(resultado, vuln, cs, init, mapas)
        linhas.append({"aplicacao": app, "unidade": u["id"], "ferramenta": u["ferramenta"],
                       "estagio": u["estagio"], "score": u["score"],
                       "tipo_pacote": resultado.get("Type"), "pacote": vuln["PkgName"],
                       "cve": vuln["VulnerabilityID"], "containers": "|".join(cs),
                       "em_uso_s1": int(a), "em_uso_s2": int(b), "em_uso_s3": int(c3),
                       "em_uso": int(a or b),  # definição registrada (S1 ou S2)
                       "executado_na_inicializacao": int(ini),
                       "carregado": int(a or b or c3 or ini),  # pós-registro: + S3 + init
                       "vinculos": "|".join(sorted(u["vinculos"]))})
    return linhas


# --- P4 orientada a ações (docs/p4-acoes.md): todos os registros do Trivy de imagem ---------

RELATORIOS_IMAGEM = {
    "dvwa": ["reports-0a8e877_trivy-report.json"],  # no artefato dos autores
    "teastore": sorted(f"coletas/teastore/trivy/image-{s}.json" for s in TEASTORE),
    "juice-shop": ["pilotos/trivy/juice-shop-image.json"],
}


def ler_relatorio(caminho, autores):
    base = autores / "data/raw" / caminho if caminho.startswith("reports-") else ETAPA / caminho
    return json.loads(base.read_text(encoding="utf-8"))


def fontes_dpkg(container):
    """Pacote binário -> pacote fonte, do banco do dpkg (status ou status.d, distroless)."""
    textos = []
    for caminho in ("/var/lib/dpkg/status", "/var/lib/dpkg/status.d"):
        tar = subprocess.run(["docker", "cp", f"{container}:{caminho}", "-"], capture_output=True)
        if tar.returncode != 0:
            continue
        with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as t:
            for m in t.getmembers():
                if m.isfile() and not m.name.endswith(".md5sums"):
                    textos.append(t.extractfile(m).read().decode("utf-8", "replace"))
    fontes = {}
    for bloco in "\n\n".join(textos).split("\n\n"):
        campos = dict(l.split(": ", 1) for l in bloco.splitlines() if ": " in l and l[0] != " ")
        if "Package" in campos:
            fontes[campos["Package"]] = campos.get("Source", campos["Package"]).split(" ")[0]
    return fontes


def arquivos_por_pacote(mapa):
    """Do mapa arquivo -> pacotes, os executáveis e as sonames de cada pacote."""
    exe, so = {}, {}
    for caminho, pacotes in mapa.items():
        p = PurePosixPath(caminho)
        for pk in pacotes:
            if p.parent.name in ("bin", "sbin"):
                exe.setdefault(pk, set()).add(p.name)
            if p.name.startswith("lib") and ".so" in p.name:
                so.setdefault(pk, set()).add(p.name)
    return exe, so


def gatilhos_extras(container):
    """Healthcheck da imagem e arquivos de cron: lugares onde um executável roda sem estar
    em execução no momento da observação (verificação S5)."""
    cfg = json.loads(subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config}}", container],
        capture_output=True, text=True, check=True).stdout)
    texto = " ".join((cfg.get("Healthcheck") or {}).get("Test") or [])
    r = subprocess.run(["docker", "run", "--rm", f"--pid=container:{container}", "--cap-add",
                        "SYS_PTRACE", AUXILIAR, "sh", "-c",
                        "cat /proc/1/root/etc/crontab /proc/1/root/etc/cron.d/* "
                        "/proc/1/root/var/spool/cron/crontabs/* 2>/dev/null"],
                       capture_output=True, text=True)
    return set((texto + "\n" + r.stdout).replace(";", " ").split())


def pacotes_da_inicializacao(container, mapa, tokens):
    """Pós-registro (falso negativo achado pela verificação S5): o interpretador dos scripts de
    inicialização (linha #!) e os executáveis citados nesses scripts rodam e carregam
    bibliotecas antes do processo principal. Devolve os pacotes desses executáveis e das
    bibliotecas que eles carregam (ldd dentro do contêiner)."""
    cfg = json.loads(subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config}}", container],
        capture_output=True, text=True, check=True).stdout)
    texto = " ".join((cfg.get("Entrypoint") or []) + (cfg.get("Cmd") or []))
    scripts = {t.strip(";&'\"") for t in texto.split() if t.endswith(".sh")}
    interpretes = set()
    for s in scripts:
        caminho = s if s.startswith("/") else f"/usr/local/bin/{s}"
        r = subprocess.run(["docker", "exec", container, "head", "-1", caminho],
                           capture_output=True, text=True)
        linha = r.stdout.strip()
        if linha.startswith("#!"):
            partes = linha[2:].split()
            interpretes.add(partes[1] if PurePosixPath(partes[0]).name == "env" and len(partes) > 1
                            else PurePosixPath(partes[0]).name)
    executaveis = {c for c in mapa if PurePosixPath(c).parent.name in ("bin", "sbin")
                   and PurePosixPath(c).name in tokens}
    caminhos = set()
    for nome in interpretes:
        r = subprocess.run(["docker", "exec", container, "sh", "-c", f"command -v {nome}"],
                           capture_output=True, text=True)
        executaveis |= {x.strip() for x in r.stdout.splitlines() if x.startswith("/")}
    if executaveis:
        r = subprocess.run(["docker", "exec", container, "sh", "-c",
                            'for p in "$@"; do [ -f "$p" ] && echo "$p" && ldd "$p"; done; true',
                            "_", *sorted(executaveis)], capture_output=True, text=True)
        for linha in r.stdout.splitlines():
            for t in linha.split():
                if t.startswith("/"):
                    caminhos.add(t)
    return pacotes_carregados({"caminhos": caminhos}, mapa), sorted(interpretes)


def requires_npm(container, raiz, pacotes):
    """Arquivos .js/.ts fora da pasta do próprio pacote que importam cada pacote npm por nome
    (require("x"), require('x'), from "x", from 'x'). Indício de carregamento tardio (S5)."""
    if not pacotes:
        return {}
    formas = ("require({q}{p}{q})", "from {q}{p}{q}", "import({q}{p}{q})")
    padroes = {f.format(q=q, p=p): p for p in pacotes for q in ('"', "'") for f in formas}
    r = subprocess.run(["docker", "run", "--rm", "-i", f"--pid=container:{container}",
                        "--cap-add", "SYS_PTRACE", AUXILIAR, "sh", "-c",
                        f"cat > /tmp/p; find /proc/1/root/{raiz} \\( -name '*.js' -o -name '*.ts' "
                        "-o -name '*.cjs' -o -name '*.mjs' \\) -type f "
                        "-exec grep -oHF -f /tmp/p {} + 2>/dev/null; true"],
                       input="\n".join(sorted(padroes)) + "\n", capture_output=True, text=True)
    achados = {}
    for linha in r.stdout.splitlines():
        arquivo, _, s = linha.partition(":")
        nome = padroes.get(s)
        arquivo = arquivo.removeprefix("/proc/1/root")
        if nome in pacotes and f"/node_modules/{nome}/" not in arquivo:
            achados.setdefault(nome, set()).add(arquivo)
    return achados


def sonames_citadas(container, caminhos, sonames):
    """Quais sonames aparecem como texto dentro de arquivos carregados (indício de dlopen)."""
    if not sonames or not caminhos:
        return {}
    alvos = [f"/proc/1/root{c}" for c in sorted(caminhos)
             if ".so" in c or "/bin/" in c or "/sbin/" in c]
    r = subprocess.run(["docker", "run", "--rm", "-i", f"--pid=container:{container}",
                        "--cap-add", "SYS_PTRACE", AUXILIAR, "sh", "-c",
                        'cat > /tmp/p; grep -aoHF -f /tmp/p "$@" 2>/dev/null; true', "_", *alvos],
                       input="\n".join(sorted(sonames)) + "\n", capture_output=True, text=True)
    achados = {}
    for linha in r.stdout.splitlines():
        arquivo, _, s = linha.rpartition(":")
        arquivo = arquivo.removeprefix("/proc/1/root")
        if s in sonames and PurePosixPath(arquivo).name != s:
            achados.setdefault(s, set()).add(arquivo)
    return achados


def coletar_imagem(app, autores, saida_bruta, spider, s4):
    """Classifica todos os registros do Trivy de imagem do alvo e grava o que for preciso para
    refazer a classificação e a verificação S5 sem os contêineres."""
    cfg = ALVOS[app]
    mapas, init, s1, s2, s3 = observar_alvo(app, saida_bruta, spider)
    pac = [{c: pacotes_carregados(s[c], mapas[c]) for c in cfg["containers"]} for s in (s1, s2, s3)]
    fontes = {c: fontes_dpkg(c) for c in cfg["containers"]}
    extras = {c: gatilhos_extras(c) for c in cfg["containers"]}
    init_pac = {c: pacotes_da_inicializacao(c, mapas[c], init[c]) for c in cfg["containers"]}
    linhas = []
    for caminho in RELATORIOS_IMAGEM[app]:
        dados = ler_relatorio(caminho, autores)
        so = (dados.get("Metadata", {}).get("OS") or {})
        base = f"{so.get('Family', '?')} {so.get('Name', '?')}"
        cs = container_do_relatorio(app, caminho)
        for i, resultado in enumerate(dados.get("Results") or []):
            for j, vuln in enumerate(resultado.get("Vulnerabilities") or []):
                obs = [em_uso(resultado, vuln, cs, s, p) for s, p in zip((s1, s2, s3), pac)]
                ini = executado_na_inicializacao(resultado, vuln, cs, init, mapas)
                tipo, nome = resultado.get("Type"), vuln["PkgName"]
                autenticado = (tipo == "node-pkg" and "/" + str(PurePosixPath(
                    vuln.get("PkgPath", "")).parent) + "/" in s4)
                fonte = next((fontes[c][nome] for c in cs if nome in fontes[c]), nome) \
                    if tipo in ("debian", "ubuntu") else nome
                linhas.append({
                    "aplicacao": app, "relatorio": caminho, "imagem_base": base,
                    "eosl": int(bool(so.get("EOSL"))), "resultado": i, "indice": j,
                    "tipo_pacote": tipo, "pacote": nome, "pacote_fonte": fonte,
                    "versao": vuln.get("InstalledVersion"),
                    "versao_corrigida": vuln.get("FixedVersion") or "",
                    "cve": vuln["VulnerabilityID"],
                    "purl": (vuln.get("PkgIdentifier") or {}).get("PURL", ""),
                    "containers": "|".join(cs),
                    "s1": int(obs[0]), "s2": int(obs[1]), "s3": int(obs[2]),
                    "inicializacao": int(ini), "s4_autenticado": int(autenticado),
                    # Definição registrada em docs/p4-acoes.md.
                    "carregado_registrado": int(any(obs) or ini or autenticado)})
                # Pós-registro: interpretador da inicialização e as bibliotecas que ele carrega.
                interp = tipo in ("debian", "ubuntu") and any(nome in init_pac[c][0] for c in cs)
                linhas[-1]["interprete_inicializacao"] = int(interp)
                linhas[-1]["carregado"] = int(linhas[-1]["carregado_registrado"] or interp)
    # Dados para a verificação S5 (falso negativo) feita depois, sem os contêineres.
    s5 = {}
    for c in cfg["containers"]:
        # Por contêiner: um pacote carregado num serviço pode não estar carregado em outro.
        do_c = [l for l in linhas if c in l["containers"].split("|")
                and l["tipo_pacote"] in ("debian", "ubuntu")]
        # Definição registrada: assim a verificação S5 continua vendo os falsos negativos que
        # a correção pós-registro resolveu.
        nao_carregados = ({l["pacote"] for l in do_c}
                          - {l["pacote"] for l in do_c if l["carregado_registrado"]})
        exe, sonames = arquivos_por_pacote(mapas[c])
        alvo_so = {s for pk in nao_carregados for s in sonames.get(pk, ())}
        caminhos = s1[c]["caminhos"] | s2[c]["caminhos"] | s3[c]["caminhos"]
        citadas = sonames_citadas(c, caminhos, alvo_so)
        s5[c] = {"executaveis": {pk: sorted(exe[pk]) for pk in nao_carregados if pk in exe},
                 "sonames": {pk: sorted(sonames[pk]) for pk in nao_carregados if pk in sonames},
                 "gatilhos": sorted(init[c] | extras[c]),
                 "interpretes_inicializacao": init_pac[c][1],
                 "pacotes_interpretes": sorted(init_pac[c][0]),
                 "sonames_citadas": {s: sorted(v) for s, v in citadas.items()}}
        npm = [l for l in linhas if c in l["containers"].split("|")
               and l["tipo_pacote"] == "node-pkg"]
        if npm:
            nl_npm = {l["pacote"] for l in npm} - {l["pacote"] for l in npm
                                                   if l["carregado_registrado"]}
            raiz = ALVOS[app].get("raiz_node", "juice-shop")
            modulos = s1[c]["modulos"] | s2[c]["modulos"] | s3[c]["modulos"]
            s5[c]["requires_npm"] = {
                pk: [{"arquivo": a, "arquivo_carregado": int(a in modulos)} for a in sorted(v)]
                for pk, v in requires_npm(c, raiz, nl_npm).items()}
            s5[c]["npm_nao_carregados"] = sorted(nl_npm)
    (saida_bruta / f"{app}--s5.json").write_text(json.dumps(s5, indent=1, ensure_ascii=False),
                                                 encoding="utf-8")
    return linhas


def main_imagem(a, spider):
    bruto = ETAPA / "pilotos/contexto-acoes"
    bruto.mkdir(parents=True, exist_ok=True)
    s4_arq = ETAPA / "pilotos/contexto/juice-shop--juice-r--s4-autenticado.txt"
    s4 = s4_arq.read_text(encoding="utf-8") if s4_arq.exists() else ""
    linhas = []
    for app in a.apps:
        linhas += coletar_imagem(app, a.autores, bruto, spider, s4 if app == "juice-shop" else "")
    destino = ETAPA / "results/contexto_imagem.csv"
    with destino.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0]))
        w.writeheader()
        w.writerows(linhas)
    for app in a.apps:
        ls = [x for x in linhas if x["aplicacao"] == app]
        print(f"{app}: {len(ls)} registros, carregados {sum(x['carregado'] for x in ls)}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--imagem", action="store_true",
                   help="P4 orientada a ações: classifica todos os registros do Trivy de imagem "
                        "(results/contexto_imagem.csv, observações em pilotos/contexto-acoes/)")
    p.add_argument("--autores", type=Path, required=True,
                   help="Clone do artefato dos autores (para o relatório Trivy da DVWA)")
    p.add_argument("--apps", nargs="+", default=list(ALVOS))
    p.add_argument("--out", type=Path, default=ETAPA / "results/contexto_execucao.csv")
    for app in ALVOS:
        p.add_argument("--spider-" + app, nargs="*",
                       help="URLs iniciais do spider do ZAP, vistas de dentro da rede Docker")
    a = p.parse_args()
    spider = {app: [u.strip() for u in getattr(a, "spider_" + app.replace("-", "_")) or []]
              for app in ALVOS}
    if a.imagem:
        return main_imagem(a, spider)
    bruto = ETAPA / "pilotos/contexto"
    bruto.mkdir(parents=True, exist_ok=True)
    linhas = []
    for app in a.apps:
        linhas += coletar(app, a.autores, bruto, spider)
    with a.out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0]))
        w.writeheader()
        w.writerows(linhas)
    for app in a.apps:
        ls = [x for x in linhas if x["aplicacao"] == app]
        altos = [x for x in ls if (x["score"] or 0) >= 7]
        estaveis = sum(x["em_uso_s1"] == x["em_uso_s2"] for x in altos)
        print(f"{app}: indiretos {len(ls)}, em uso {sum(x['em_uso'] for x in ls)}; "
              f">=7: {len(altos)}, em uso {sum(x['em_uso'] for x in altos)}, "
              f"S1=S2 em {estaveis}/{len(altos)}")


if __name__ == "__main__":
    main()
