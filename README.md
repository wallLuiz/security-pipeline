# Security Pipeline — Análise Automatizada de Segurança

Pipeline para análise de segurança de aplicações que integra **SAST**, **DAST** e **SCA**, além de **Inteligência Artificial** para auxiliar na interpretação dos resultados de SAST e DAST.

Todas as ferramentas rodam em containers isolados, orquestrados com Docker Compose, e os resultados são centralizados em relatórios estruturados na pasta `reports/`.

> **Projeto acadêmico — Segurança da Informação.** Os resultados são apoio à triagem e não substituem a validação técnica.

## 1. Funcionalidades

| Etapa | Ferramenta | Descrição |
|---|---|---|
| SAST | Semgrep | Identifica possíveis vulnerabilidades no código-fonte. |
| DAST | OWASP ZAP | Analisa uma aplicação em execução (modo *baseline*, passivo). |
| SCA | OSV.dev | Consulta vulnerabilidades conhecidas nas dependências npm. |
| Enriquecimento | DeepSeek API | Analisa os achados de SAST e DAST (risco, severidade real, possível falso positivo e correção) e gera o relatório consolidado. |

> **Nota:** os resultados do SCA são listados no relatório diretamente a partir do OSV.dev, **sem passar pela IA**.

## 2. Como funciona

```
GitHub (repo-alvo) → git-clone → workspace/repository ─┬─► Semgrep ─► reports/semgrep.json ─┐
                                                       └─► package-lock.json ─► OSV.dev ────┤
Aplicação em execução ◄── OWASP ZAP ─► reports/zap-lab.json | zap.json ─────────────────────┤
                                                                                            ▼
                                                  enricher (Python) ─► DeepSeek API (SAST/DAST)
                                                                                            ▼
                                                                  reports/enriched.md e enriched.json
```

Os serviços se comunicam por um volume compartilhado (`reports/`), pela rede interna do Compose (ZAP → aplicação) e por HTTPS (enricher → DeepSeek e OSV.dev).

## 3. Tecnologias

- Docker e Docker Compose
- Semgrep e OWASP ZAP (imagens oficiais)
- OSV.dev (API pública)
- DeepSeek API (compatível com o SDK da OpenAI)
- Python 3.12 (dentro da imagem do enricher)
- Node.js 22 (apenas em container, para gerar `package-lock.json` quando necessário)

Na sua máquina, só são necessários **Git** e **Docker**. Python e Node.js **não** precisam ser instalados.

## 4. Pré-requisitos

- [Git](https://git-scm.com/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (deve estar **em execução**)
- Uma chave de API da [DeepSeek](https://platform.deepseek.com/) (pode exigir saldo na conta)

Verifique as instalações:

```powershell
git --version
docker --version
docker compose version
docker info
```

> Os comandos deste README estão em **PowerShell** (Windows). Onde há diferença para Linux/macOS, isso é indicado.
>
> Evite colocar o projeto dentro do **OneDrive**: a sincronização de milhares de arquivos clonados causa lentidão e erros de arquivo bloqueado. Prefira um caminho como `C:\dev\security-pipeline`.

## 5. Instalação e configuração

Clone este projeto e entre na pasta:

```powershell
git clone https://github.com/SEU-USUARIO/SEU-REPOSITORIO.git
cd SEU-REPOSITORIO
```

*(Substitua a URL pelo endereço real deste repositório.)*

Crie o arquivo `.env` a partir do modelo e edite-o:

```powershell
copy .env.example .env      # Linux/macOS: cp .env.example .env
```

| Variável | Descrição | Padrão no enricher |
|---|---|---|
| `GITHUB_REPO_URL` | Repositório que será analisado. | — (obrigatória) |
| `DEEPSEEK_API_KEY` | Chave da API da DeepSeek. | — (obrigatória) |
| `DEEPSEEK_MODEL` | Modelo da DeepSeek. Confira o nome atual na documentação da DeepSeek. | `deepseek-chat` |
| `MAX_ITEMS` | Máximo de grupos de achados enviados à IA, por ferramenta (SAST e DAST). | `10` |
| `OSV_LIMIT` | Limite de dependências consultadas no OSV.dev. | `100` |
| `ZAP_REPORT` | Relatório DAST lido pelo enricher (`zap-lab.json` ou `zap.json`). | `zap-lab.json` |
| `APP_TARGET_URL` | URL da aplicação para o serviço `zap` (DAST externo). | — |

> **Todas as variáveis devem existir no `.env`**, mesmo as que você não usa na execução atual, porque o Compose valida o arquivo inteiro a cada comando.

**Segurança:** nunca publique o `.env` no GitHub. Confirme que o `.gitignore` contém:

```gitignore
.env
reports/
workspace/
```

Se a chave de API for exposta por engano, revogue-a no painel da DeepSeek e gere outra.

## 6. Execução do pipeline

Execute as etapas na ordem abaixo.

### 6.1. Clonagem do repositório-alvo

```powershell
docker compose run --rm git-clone
```

Remove a clonagem anterior e baixa o repositório de `GITHUB_REPO_URL` (clone raso, apenas o último commit) em `workspace/repository/`.

### 6.2. Análise estática — SAST

```powershell
docker compose run --rm --no-deps semgrep
```

Gera `reports/semgrep.json`, com as regras acionadas, a localização dos achados e a severidade atribuída pela ferramenta. A opção `--config auto` baixa as regras adequadas às linguagens detectadas, por isso exige acesso à internet.

### 6.3. Análise dinâmica — DAST

O projeto oferece duas formas de execução. Escolha uma.

**Opção A — Laboratório local (OWASP Juice Shop)**

```powershell
docker compose --profile lab up --abort-on-container-exit --exit-code-from zap-lab zap-lab
docker compose --profile lab down
```

Sobe a aplicação em container, aguarda 30 segundos e executa o ZAP. Gera `reports/zap-lab.json` e `reports/zap-lab.html`. Mantenha `ZAP_REPORT=zap-lab.json` no `.env`.

**Opção B — Aplicação externa**

Configure `APP_TARGET_URL` no `.env` e execute:

```powershell
docker compose run --rm zap
```

Gera `reports/zap.json` e `reports/zap.html`. Para usar esse relatório no enriquecimento, defina `ZAP_REPORT=zap.json` no `.env`.

Observações:

- O alvo precisa ser **acessível a partir do container do ZAP**. `host.docker.internal` aponta para a máquina hospedeira (já configurado no `docker-compose.yml` para funcionar também no Linux).
- Use apenas aplicações **próprias** ou com **autorização expressa** de teste.
- O scanner é o `zap-baseline.py`: faz rastreamento (*spider*) e varredura **passiva**, sem enviar ataques. Vulnerabilidades que dependem de testes ativos (por exemplo, injeção SQL) podem não ser detectadas, e os alertas precisam ser validados.
- A espera de 30 segundos no laboratório é fixa. Em máquinas lentas, aumente o valor se o ZAP não conseguir conectar.

### 6.4. Análise de dependências — SCA

O enricher consulta o OSV.dev com base no arquivo `package-lock.json` **na raiz** do repositório clonado (formatos npm versão 2 e 3, incluindo dependências aninhadas).

Se o projeto já possui um lockfile compatível, não é preciso fazer nada. Se não possui, gere-o **depois de cada clonagem** (o `git-clone` apaga a pasta a cada execução).

PowerShell:

```powershell
$repo = (Resolve-Path .\workspace\repository).Path
docker run --rm -v "${repo}:/app" -w /app node:22-alpine npm install --package-lock-only --ignore-scripts --no-audit --no-fund
```

Linux/macOS:

```bash
docker run --rm -v "$PWD/workspace/repository:/app" -w /app node:22-alpine npm install --package-lock-only --ignore-scripts --no-audit --no-fund
```

O comando gera o inventário de dependências sem executar scripts de instalação. Se não houver `package-lock.json`, a etapa SCA é ignorada e o restante do pipeline continua.

### 6.5. Enriquecimento com IA e relatório

```powershell
docker compose run --rm --build enricher
```

O serviço:

1. Lê os resultados do Semgrep.
2. Lê o relatório do ZAP indicado em `ZAP_REPORT`.
3. Agrupa os achados por regra (SAST) ou tipo de alerta (DAST), prioriza por severidade e limita a `MAX_ITEMS`.
4. Envia os grupos selecionados à DeepSeek, com o trecho mínimo de código e **mascaramento** de padrões de segredos.
5. Consulta as dependências npm no OSV.dev.
6. Gera os relatórios consolidados.

Arquivos gerados:

```text
reports/enriched.json   # dados estruturados
reports/enriched.md     # relatório legível
```

Se a API da DeepSeek falhar para algum item, a falha é registrada no relatório e o processamento continua.

### Execução rápida (laboratório com Juice Shop)

```powershell
docker compose run --rm git-clone
docker compose run --rm --no-deps semgrep
docker compose --profile lab up --abort-on-container-exit --exit-code-from zap-lab zap-lab
docker compose --profile lab down
docker compose run --rm --build enricher
```

## 7. Estrutura do projeto

```text
.
├── docker-compose.yml
├── .env.example
├── enricher/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── enrich.py
│   └── osv_client.py
├── reports/          # gerada na execução (fora do Git)
└── workspace/        # repositório clonado (fora do Git)
```

## 8. Relatórios gerados

| Arquivo | Descrição |
|---|---|
| `semgrep.json` | Resultado bruto do SAST. |
| `zap-lab.json` / `zap-lab.html` | Resultado do DAST no laboratório local. |
| `zap.json` / `zap.html` | Resultado do DAST na aplicação externa. |
| `enriched.json` | Resultado consolidado (SAST, DAST e SCA) em JSON. |
| `enriched.md` | Relatório consolidado em Markdown. |

Os arquivos de DAST dependem da opção executada. Os relatórios finais são gerados pelo serviço `enricher`.

## 9. Analisando outro repositório

Altere `GITHUB_REPO_URL` no `.env`:

```env
GITHUB_REPO_URL=https://github.com/ORGANIZACAO/OUTRO-PROJETO.git
```

Depois, repita as etapas a partir da clonagem (6.1).

**Limitações:**

- **SAST:** funciona com diferentes linguagens, conforme as regras disponíveis no Semgrep.
- **DAST:** exige uma aplicação **em execução e acessível** pelo ZAP. Trocar a URL do GitHub **não** inicia a aplicação clonada.
- **SCA:** implementado apenas para dependências **npm** com `package-lock.json` na raiz. Projetos com vários `package.json` em subpastas ou outros ecossistemas não são cobertos. Um lockfile gerado com `--package-lock-only` reflete as versões resolvidas **no dia da geração**, não necessariamente as usadas em produção.
- **IA:** as respostas não são determinísticas, podem conter imprecisões e dependem de uma chave válida. Apenas os `MAX_ITEMS` grupos mais críticos de cada ferramenta são enriquecidos.
- **Reprodutibilidade:** o modelo é acessado por API e pode mudar ao longo do tempo.

## 10. Segurança, privacidade e boas práticas

- **Dados enviados a terceiros:** trechos de código e achados de SAST/DAST são enviados à **API da DeepSeek**, e nomes e versões de pacotes são enviados ao **OSV.dev**. O mascaramento de segredos usa expressões regulares e **não captura todos os casos**. Não use o pipeline em código confidencial sem avaliar a política da sua organização e a LGPD.
- Não publique chaves de API nem o arquivo `.env`.
- Execute o DAST somente em ambientes autorizados e, de preferência, nunca em produção.
- Valide os resultados automatizados antes de classificá-los como vulnerabilidades confirmadas.
- Relatórios podem conter caminhos, trechos de código e informações do projeto analisado. Compartilhe com cuidado.

## 11. Solução de problemas

| Sintoma | Causa provável | O que fazer |
|---|---|---|
| `error during connect` / `cannot connect to the Docker daemon` | Docker Desktop fechado. | Abra o Docker Desktop e aguarde iniciar. |
| `Configure ... no .env` | Variável obrigatória ausente. | Complete o `.env` com base no `.env.example`. |
| Erro `401` na etapa de IA | Chave inválida. | Confira `DEEPSEEK_API_KEY` (sem aspas nem espaços). |
| Erro `402` na etapa de IA | Sem saldo na conta. | Adicione saldo na DeepSeek. |
| Relatório sem a seção DAST | `ZAP_REPORT` aponta para um arquivo que não existe. | Ajuste para `zap-lab.json` ou `zap.json` conforme a opção executada. |
| ZAP não conecta ao alvo | Aplicação ainda iniciando ou URL inacessível. | Aumente a espera (laboratório) ou revise `APP_TARGET_URL`. |
| `ModuleNotFoundError: osv_client` | Imagem do enricher desatualizada. | Rode `docker compose build enricher` e confirme o `COPY *.py .` no Dockerfile. |
| SCA ignorado | Sem `package-lock.json` na raiz. | Gere o lockfile (seção 6.4). |
| Lentidão ou arquivos bloqueados | Projeto dentro do OneDrive. | Mova o projeto para uma pasta fora do OneDrive. |

## 12. Objetivo acadêmico

O Security Pipeline foi desenvolvido para demonstrar a integração de diferentes técnicas de análise de segurança em um fluxo automatizado, reunindo análise estática, análise dinâmica, consulta de vulnerabilidades em dependências e enriquecimento dos resultados com Inteligência Artificial, a fim de facilitar a identificação e a interpretação de possíveis riscos em aplicações de software.