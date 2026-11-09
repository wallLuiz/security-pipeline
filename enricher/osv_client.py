
import json
import requests
from pathlib import Path

OSV_API_URL = "https://api.osv.dev/v1/query"
TIMEOUT = 30


def consultar_vulnerabilidades(pacote, ecossistema, versao):
    """Consulta vulnerabilidades conhecidas de um pacote no OSV.dev."""

    payload = {
        "version": versao,
        "package": {
            "name": pacote,
            "ecosystem": ecossistema
        }
    }

    try:
        resposta = requests.post(
            OSV_API_URL,
            json=payload,
            timeout=TIMEOUT
        )
        resposta.raise_for_status()
        return resposta.json().get("vulns", [])

    except requests.RequestException as erro:
        print(f"[ERRO OSV] {pacote}@{versao}: {erro}")
        return []


def extrair_dependencias_npm(caminho_lock):
    """
    Extrai dependências do package-lock.json.
    Compatível com lockfiles npm versão 2 e 3.
    """

    lockfile_path = Path(caminho_lock)

    if not lockfile_path.exists():
        print(f"[AVISO OSV] Arquivo não encontrado: {lockfile_path}")
        return []

    try:
        with lockfile_path.open("r", encoding="utf-8") as arquivo:
            dados = json.load(arquivo)

    except (json.JSONDecodeError, OSError) as erro:
        print(f"[ERRO OSV] Falha ao ler lockfile: {erro}")
        return []

    pacotes = dados.get("packages", {})
    dependencias = []

    for package_path, informacoes in pacotes.items():

        package_path = str(package_path)

        if not package_path.startswith("node_modules/"):
            continue

        caminho_pacote = package_path.rsplit("node_modules/", 1)[-1]
        partes = caminho_pacote.split("/")

        if partes[0].startswith("@"):
            if len(partes) < 2:
                continue

            nome = "/".join(partes[:2])
        else:
            nome = partes[0]

        versao = informacoes.get("version")

        if not nome or not versao:
            continue

        dependencias.append({
            "name": nome,
            "version": versao,
            "ecosystem": "npm",
            "dev": informacoes.get("dev", False)
        })

    return dependencias



def consultar_dependencias_npm(caminho_lock, limite=0, tamanho_lote=100):
    """
    Consulta dependências npm no OSV.dev utilizando a Batch API.

    limite=0 significa consultar todas as dependências identificadas.
    """

    dependencias = extrair_dependencias_npm(caminho_lock)

    selecionadas = (
        dependencias[:limite]
        if limite > 0
        else dependencias
    )

    resultados = []
    erros = 0
    consultadas = 0

    print(f"[OSV] Dependências identificadas: {len(dependencias)}")
    print(f"[OSV] Dependências selecionadas: {len(selecionadas)}")

    for inicio in range(0, len(selecionadas), tamanho_lote):

        lote = selecionadas[inicio:inicio + tamanho_lote]

        consultas = [
            {
                "package": {
                    "name": dependencia["name"],
                    "ecosystem": "npm"
                },
                "version": dependencia["version"]
            }
            for dependencia in lote
        ]

        try:
            resposta = requests.post(
                "https://api.osv.dev/v1/querybatch",
                json={"queries": consultas},
                timeout=60
            )

            resposta.raise_for_status()
            dados = resposta.json()

            respostas = dados.get("results", [])

            if len(respostas) != len(lote):
                raise ValueError(
                    "Quantidade de resultados diferente "
                    "da quantidade de consultas enviadas."
                )

        except (requests.RequestException, ValueError) as erro:
            print(f"[ERRO OSV] Falha no lote {inicio // tamanho_lote + 1}: {erro}")
            erros += len(lote)
            continue

        consultadas += len(lote)

        for dependencia, resultado in zip(lote, respostas):

            vulnerabilidades = resultado.get("vulns", [])

            if resultado.get("error"):
                erros += 1
                consultadas -= 1
                print(
                    f"[ERRO OSV] {dependencia['name']}@"
                    f"{dependencia['version']}: {resultado['error']}"
                )
                continue

            if vulnerabilidades:
                resultados.append({
                    **dependencia,
                    "vulnerabilities": vulnerabilidades
                })

            print(
                f"[OSV] {dependencia['name']}@{dependencia['version']}: "
                f"{len(vulnerabilidades)} vulnerabilidade(s)"
            )

        print(
            f"[OSV] Lote {inicio // tamanho_lote + 1} concluído "
            f"({len(lote)} dependências)."
        )

    return {
        "total_dependencies": len(dependencias),
        "dependencies_selected": len(selecionadas),
        "dependencies_consulted": consultadas,
        "dependencies_with_vulnerabilities": len(resultados),
        "vulnerable_dependencies": resultados,
        "errors": erros
    }

