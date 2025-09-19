## Auto_Security plan.md

### Purpose
Anchor AI coding assistants with a pragmatic, demo-safe plan to build an agentic workflow that: (1) scouts the public web for exposed assets/evidence, (2) pentests a controlled demo target (NodeZero if available, otherwise simulated), (3) triages findings and opens remediation PRs, (4) verifies fixes. Explicitly flags auth/role constraints to avoid mid-demo blockers.

### Guardrails and access constraints
- **Authorized targets only**: External testing must target assets you own/control and have explicitly authorized.
- **NodeZero roles/tokens**: External scans require org access, API token, and roles (e.g., `NODEZERO_RUNNER`, `ORG_ADMIN`) and assets must be authorized within an Asset Group before a run.
- **Fallbacks for demo**: If NodeZero access is unavailable, use a deterministic, explainable scanner against your demo repo.

### Key doc takeaways (read first)
- **NodeZero GraphQL API**: Great for programmatic pentest orchestration. External runs require creating Asset Groups and authorizing assets in the portal before starting runs. Use only with proper org access and permissions. `https://docs.horizon3.ai`
- **Bright Data MCP Server**: Provides reliable, on-demand web access for LLMs/agents (free tier ~5k MCP req/mo). Prefer MCP over ad‑hoc scraping for consistent, cached retrievals. Example server and docs available. `https://docs.brightdata.com` · `https://github.com/brightdata/brightdata-mcp`
- **Redis Stack (Vectors)**: Production-grade vector fields with KNN and hybrid filtering; quickstart via Docker; RedisInsight helps inspect indices. Recommended for demos. `https://redis.io/docs/latest/stack/` · `https://redis.io/docs/latest/develop/interact/search-and-query/semantic/`
- **LlamaIndex + RedisVectorStore**: Official integration supports custom index names and metadata filtering; use it to persist Scout/Pentest documents and power triage queries. `https://docs.llamaindex.ai`
- **Practical constraint**: Real NodeZero runs often need paid/sandbox access and asset authorization. For hack demos: attempt NodeZero if you have access; otherwise run a deterministic, repeatable simulated scanner with realistic findings + evidence.

## 5‑Hour Sprint Plan (realistic, demo‑safe)
Goal: demo an agent team that uses Bright Data MCP + LlamaIndex + Redis; optionally NodeZero.
Assumptions: demo vulnerable repo you own; Redis Stack via Docker; LLM key (e.g., OpenAI) for LlamaIndex; NodeZero creds optional.

### Hour 0 → 0:30 — Setup & quick read
- **Start Redis Stack locally**
```bash
docker run --name redis-vecdb -d -p 6379:6379 -p 8001:8001 redis/redis-stack:latest
```
- **Clone Bright Data MCP example**
```bash
git clone https://github.com/brightdata/brightdata-mcp
```
- **Install Python libs**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install --upgrade pip
pip install llama-index redis requests beautifulsoup4 fastapi uvicorn pydantic pygithub
# If using Bright Data SDK, install their package per docs
```

### Hour 0:30 → 1:30 — Ingest: Scout Agent (MCP → LlamaIndex → Redis)
- **If using Bright Data MCP**: Call MCP server endpoints to fetch structured page content. Cache responses for reliability.
- **Fallback (deterministic)**: Use `requests` + `BeautifulSoup` to fetch demo‑safe pages or your staging site.
- **Indexing**: Convert each page into a `Document` with metadata and persist to Redis via `RedisVectorStore`.
```python
from datetime import datetime
from llama_index.core import Document
from llama_index.vector_stores.redis import RedisVectorStore

rstore = RedisVectorStore(redis_url="redis://localhost:6379", index_name="scout_index")
page_text = "..."  # fetched and cleaned text
url = "https://example.com/path"
doc = Document(text=page_text, metadata={
    "source": url,
    "agent": "scout",
    "crawl_time": datetime.utcnow().isoformat(),
})
rstore.add_documents([doc])
```

### Hour 1:30 → 2:30 — Pentest Agent (NodeZero if available; else deterministic scanner)
- **Option A — NodeZero GraphQL**
  - Create Asset Group (mutation) → Provision assets discovered by Scout → Start pentest run → Poll for results.
  - Parse findings into your `Finding` schema and push to Redis/LlamaIndex.
  - Constraints: asset authorization required; proper roles and API token. See `https://docs.horizon3.ai`.
- **Option B — Deterministic scanner (recommended for demo)**
  - Checks to implement quickly and explainably:
    - **Hardcoded creds**: `password\s*[:=]\s*[\'\"].{3,}[\'\"]`
    - **Leaked secrets**: `AWS_SECRET_ACCESS_KEY=`, `OPENAI_API_KEY=`, etc.
    - **Exposed config**: detect `.env`, `id_rsa`, backups in repo tree.
    - **Outdated deps**: flag known-old versions in `requirements.txt` / `package.json`.
    - **Headers**: check for missing `Content-Security-Policy`, `X-Frame-Options`, etc. in demo server responses.
  - Emit `Finding` JSON with `id`, `type`, `severity`, `confidence`, `evidence` (file, line, snippet), `suggested_fix`.

### Hour 2:30 → 3:30 — Triage Agent (dedupe, prioritize, synthesize PRs)
- **Dedupe**: Use Redis KNN to find near-duplicates (k=5) with metadata filters (e.g., `asset_id`, `path`).
- **Rank**: simple score = `severity × exploitability × confidence`.
- **Generate patches**: With LlamaIndex query engine, prompt to produce unified diffs and PR bodies from evidence + file snippets.
- **Open PRs**: Use GitHub API (`PyGithub`) to create branch `fix/<finding_id>`, commit diff, open PR; tag `human_review_required: true`.
- **Example prompt**
```text
Given this file snippet and the finding (hardcoded credentials), produce a patch that:
- replaces the secret with environment variables,
- updates README with configuration instructions,
- adds a unit test that asserts secrets are not committed.
Return only: a unified diff patch and a concise PR body.
```

### Hour 3:30 → 4:00 — Verifier Agent & loop
- **Simulated PRs**: Merge, rerun deterministic scanner; findings should be resolved.
- **NodeZero**: If used, rerun targeted checks or the asset scan via GraphQL and confirm findings cleared.
- **Metrics**: log `findings_before`, `findings_after`, `avg_severity_reduced` to Redis/LlamaIndex.

### Hour 4:00 → 5:00 — Polish + Demo
- **Minimal UI/CLI**: A small FastAPI or terminal script that:
  - starts job: `scan <target>`
  - streams events: `[SCOUT]`, `[PENTEST]`, `[TRIAGE]`, `[PR_OPENED]`, `[VERIFY]`
  - on PR open: show diff summary and PR URL
- **Tracing/logging**: simple JSON logs with agent names and timestamps.
- **Safety slide**: “All scans targeted demo repo/site only. No external assets tested.”

## Concrete integration notes & snippets
- **Bright Data MCP**
  - Prefer MCP endpoints for normalized, sanitized page content; cache responses for demos. `https://docs.brightdata.com` · `https://github.com/brightdata/brightdata-mcp`
- **LlamaIndex + RedisVectorStore**
  - Pass `redis_url` and `index_name`; store metadata for filtering.
```python
from llama_index.vector_stores.redis import RedisVectorStore
store = RedisVectorStore(redis_url="redis://localhost:6379", index_name="scout_index")
```
- **Redis Vector search**
  - Use Redis Stack; debug with RedisInsight at `http://localhost:8001`. KNN + metadata filters supported. `https://redis.io/docs/latest/stack/`
- **NodeZero GraphQL**
  - Mutations for Asset Groups and pentest runs; handle pagination and long-running job polling. Assets must be authorized before external testing. `https://docs.horizon3.ai`

## Risks and fallbacks
- **NodeZero access not available**: default to deterministic scanner; keep interfaces compatible with the NodeZero path.
- **Rate limits / flaky web**: cache MCP responses; cap crawl scope to deterministic pages.
- **Vector index drift**: provide a `--rebuild-index` flag to re-embed when schemas change.

## Demo checklist
- **Redis Stack running** and reachable on 6379/8001
- **LLM key configured** for LlamaIndex (env var)
- **Optional**: NodeZero API token and roles verified; assets authorized
- **Demo repo** cloned and under control; contains seeded issues for findings
- **MCP server reachable** or fallback fetch confirmed
- **Safety statement** prepared and included in slides/docs
