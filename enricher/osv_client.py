
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


def consultar_dependencias_npm(caminho_lock, limite=100):
    """
    Consulta as dependências npm no OSV.dev.
    Retorna os resultados e estatísticas da consulta.
    """

    dependencias = extrair_dependencias_npm(caminho_lock)

    resultados = []
    erros = 0
    consultadas = min(len(dependencias), limite)

    print(f"[OSV] Dependências identificadas: {len(dependencias)}")

    for dependencia in dependencias[:limite]:

        nome = dependencia["name"]
        versao = dependencia["version"]

        try:
            resposta = requests.post(
                OSV_API_URL,
                json={
                    "version": versao,
                    "package": {
                        "name": nome,
                        "ecosystem": "npm"
                    }
                },
                timeout=TIMEOUT
            )

            resposta.raise_for_status()
            vulnerabilidades = resposta.json().get("vulns", [])

        except requests.RequestException as erro:
            print(f"[ERRO OSV] {nome}@{versao}: {erro}")
            erros += 1
            continue

        if vulnerabilidades:
            resultados.append({
                **dependencia,
                "vulnerabilities": vulnerabilidades
            })

        print(
            f"[OSV] {nome}@{versao}: "
            f"{len(vulnerabilidades)} vulnerabilidade(s)"
        )

    return {
        "total_dependencies": len(dependencias),
        "dependencies_consulted": consultadas - erros,
        "dependencies_with_vulnerabilities": len(resultados),
        "vulnerable_dependencies": resultados,
        "errors": erros
    }
