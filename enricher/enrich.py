import json, os, re
from pathlib import Path
from collections import defaultdict
from openai import OpenAI
from osv_client import consultar_dependencias_npm

client = OpenAI(api_key=os.environ["DEEPSEEK_API_KEY"],
                base_url="https://api.deepseek.com")
MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")  # confirme o nome atual na doc da DeepSeek
MAX_ITEMS = int(os.getenv("MAX_ITEMS", "10"))
OSV_LIMIT = int(os.getenv("OSV_LIMIT", "100"))
REPORTS = Path("/reports")
SRC = Path("/src")
SEV_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}

SYSTEM = ("Você é um engenheiro de AppSec. Responda em português, de forma objetiva, com: "
          "1) risco, 2) severidade real, 3) chance de falso positivo, 4) correção com exemplo.")


def strip_html(text):
    return re.sub(r"<[^>]+>", "", text or "").strip()


def mask_secrets(text):
    return re.sub(r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*\S+",
                  r"\1=<REDACTED>", text or "")


def read_snippet(path, start, end):
    """Lê o trecho direto do código (o Semgrep sem login não devolve o trecho)."""
    try:
        with open(os.path.join(SRC, path), encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
        return mask_secrets("\n".join(lines[max(start - 3, 0):min(end + 2, len(lines))]))[:800]
    except OSError:
        return ""


def ask(prompt):
    try:
        r = client.chat.completions.create(
            model=MODEL, temperature=0.2,
            messages=[{"role": "system", "content": SYSTEM},
                      {"role": "user", "content": prompt}])
        return r.choices[0].message.content
    except Exception as e:
        return f"[Falha ao consultar a IA: {e}]"


# ---------------- SAST ----------------
sast_out = []
sem_path = f"{REPORTS}/semgrep.json"
if os.path.exists(sem_path):
    results = json.load(open(sem_path)).get("results", [])
    by_rule = defaultdict(list)
    for f in results:
        by_rule[f["check_id"]].append(f)

    ordered = sorted(by_rule.items(),
                     key=lambda kv: (SEV_ORDER.get(kv[1][0]["extra"].get("severity"), 3), -len(kv[1])))
    for rule, items in ordered[:MAX_ITEMS]:
        first = items[0]
        snippet = read_snippet(first["path"], first["start"]["line"], first["end"]["line"])
        prompt = (f"Regra: {rule}\nOcorrências: {len(items)}\n"
                  f"Severidade: {first['extra'].get('severity')}\n"
                  f"Mensagem: {first['extra'].get('message')}\n"
                  f"Arquivo: {first['path']}:{first['start']['line']}\n"
                  f"Trecho:\n{snippet}")
        print(f"[SAST] {rule}")
        sast_out.append({"rule": rule, "count": len(items),
                         "severity": first["extra"].get("severity"),
                         "locations": [f"{i['path']}:{i['start']['line']}" for i in items][:20],
                         "ai_analysis": ask(prompt)})

# ---------------- DAST ----------------
dast_out = []
zap_path = f"{REPORTS}/zap.json"
if os.path.exists(zap_path):
    alerts = [a for s in json.load(open(zap_path)).get("site", []) for a in s.get("alerts", [])]
    alerts.sort(key=lambda a: -int(a.get("riskcode", 0)))
    for a in alerts[:MAX_ITEMS]:
        urls = [i.get("uri") for i in a.get("instances", [])[:3]]
        prompt = (f"Alerta ZAP: {a.get('alert')} ({a.get('riskdesc')})\n"
                  f"Descrição: {strip_html(a.get('desc'))[:800]}\n"
                  f"Solução sugerida: {strip_html(a.get('solution'))[:400]}\n"
                  f"Exemplos de URL: {urls}")
        print(f"[DAST] {a.get('alert')}")
        dast_out.append({"alert": a.get("alert"), "risk": a.get("riskdesc"),
                         "count": len(a.get("instances", [])),
                         "ai_analysis": ask(prompt)})
# ---------------- FASE 3: OSV.dev (SCA) ----------------

print("\n========== ANÁLISE SCA - OSV.dev ==========")

lock_path = SRC / "package-lock.json"

osv_out = consultar_dependencias_npm(
    lock_path,
    limite=OSV_LIMIT
)

# ---------------- Saída ----------------
json.dump({"sast": sast_out, "dast": dast_out, "osv": osv_out},
          open(f"{REPORTS}/enriched.json", "w"), indent=2, ensure_ascii=False)

with open(f"{REPORTS}/enriched.md", "w", encoding="utf-8") as md:
    md.write("# Relatório de Segurança Enriquecido\n\n## SAST (Semgrep)\n")
    for s in sast_out:
        md.write(f"\n### {s['rule']} ({s['count']}x, {s['severity']})\n"
                 f"Locais: {', '.join(s['locations'][:5])}\n\n{s['ai_analysis']}\n")
    md.write("\n## DAST (ZAP)\n")
    for d in dast_out:
        md.write(f"\n### {d['alert']} - {d['risk']} ({d['count']} ocorrências)\n\n{d['ai_analysis']}\n")
        md.write("\n## SCA - OSV.dev\n\n")

    md.write(
        f"- Dependências identificadas: "
        f"{osv_out['total_dependencies']}\n"
        f"- Dependências consultadas: "
        f"{osv_out['dependencies_consulted']}\n"
        f"- Dependências com vulnerabilidades: "
        f"{osv_out['dependencies_with_vulnerabilities']}\n"
        f"- Erros de consulta: {osv_out['errors']}\n\n"
    )

    for dependencia in osv_out["vulnerable_dependencies"]:

        md.write(
            f"\n### {dependencia['name']}@{dependencia['version']}\n"
        )

        md.write(
            f"- Ecossistema: {dependencia['ecosystem']}\n"
            f"- Dependência de desenvolvimento: "
            f"{dependencia['dev']}\n"
        )

        for vulnerabilidade in dependencia["vulnerabilities"]:

            md.write(
                f"\n**{vulnerabilidade.get('id', 'ID não informado')}**\n\n"
                f"{vulnerabilidade.get('summary', 'Sem descrição disponível')}\n\n"
            )

            aliases = vulnerabilidade.get("aliases", [])

            if aliases:
                md.write(
                    f"- Identificadores relacionados: {', '.join(aliases)}\n"
                )

        md.write("\n---\n")

print("Pronto: reports/enriched.md e reports/enriched.json")