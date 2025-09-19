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

### Hour 0:30 → 1:30 — Vulnerability Knowledge Base (Scout Agent)

#### **Core Intelligence Layer: Redis Vector Similarity Search**
- **Pull vulnerability feeds**: Use BrightData MCP to scrape vulnerability advisories, CVE databases, exploit repositories, and GitHub security patches.
- **Embed threat intelligence**: Convert vulnerability descriptions, CVE metadata, patch examples, and exploit patterns into embeddings using OpenAI's embedding model.
- **Store in Redis VL**: Persist embeddings in Redis with rich metadata for semantic similarity search.
- **Codebase analysis**: When LlamaIndex parsing surfaces suspicious patterns in target code, run vector similarity search against Redis to find semantically similar known vulnerabilities.

#### **Implementation**
```python
from datetime import datetime
from llama_index.core import Document
from llama_index.vector_stores.redis import RedisVectorStore

# Multi-index approach for different data types
vuln_store = RedisVectorStore(redis_url="redis://localhost:6379", index_name="vulnerabilities")
patches_store = RedisVectorStore(redis_url="redis://localhost:6379", index_name="patches")
codebase_store = RedisVectorStore(redis_url="redis://localhost:6379", index_name="codebase")

# Example: Store CVE data
cve_doc = Document(text=cve_description, metadata={
    "type": "vulnerability",
    "cve_id": "CVE-2023-1234",
    "severity": "critical",
    "vector_type": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "affected_packages": ["express", "lodash"],
    "crawl_time": datetime.utcnow().isoformat(),
})
vuln_store.add_documents([cve_doc])

# Example: Store patch patterns
patch_doc = Document(text=patch_diff_content, metadata={
    "type": "patch",
    "vulnerability_type": "sql_injection",
    "language": "javascript",
    "framework": "express",
    "github_url": "https://github.com/example/fix",
})
patches_store.add_documents([patch_doc])
```

### Hour 1:30 → 2:30 — Pentest Agent with Vector Intelligence Integration

#### **NodeZero + Vector Similarity Search**
- **Option A — NodeZero GraphQL**
  - Create Asset Group (mutation) → Provision assets discovered by Scout → Start pentest run → Poll for results.
  - **Intelligence enrichment**: For each NodeZero finding (e.g., "SQL injection in login route"), embed the finding description and query Redis VL to surface similar vulnerabilities + proven patches.
  - Parse findings into your `Finding` schema, enriched with vector similarity matches from threat intelligence.
  - Constraints: asset authorization required; proper roles and API token. See `https://docs.horizon3.ai`.

#### **Deterministic Scanner + Vector Context (recommended for demo)**
- **Enhanced vulnerability detection**:
  - **Hardcoded creds**: `password\s*[:=]\s*[\'\"].{3,}[\'\"]` → Query Redis VL for "credential exposure" patterns
  - **Leaked secrets**: `AWS_SECRET_ACCESS_KEY=`, `OPENAI_API_KEY=`, etc. → Vector search for "API key leakage" mitigations
  - **Exposed config**: detect `.env`, `id_rsa`, backups → Find similar "configuration exposure" fixes
  - **Outdated deps**: flag known-old versions → Vector search for specific CVE patches for detected packages
  - **Headers**: missing security headers → Query for "HTTP header hardening" solutions
- **Intelligence-driven output**: Each finding includes vector similarity matches showing related CVEs, proven patches, and CVSS context.
- Emit `Finding` JSON with `id`, `type`, `severity`, `confidence`, `evidence`, `vector_matches` (similar vulnerabilities), `suggested_patches` (from Redis VL).

### Hour 2:30 → 3:30 — Triage Agent with Vector-Driven PR Generation

#### **Intelligence-Driven Deduplication & Prioritization**
- **Vector-based dedupe**: Use Redis KNN to find semantically similar findings (k=5) with metadata filters (e.g., `asset_id`, `vulnerability_type`).
- **Context-aware ranking**: Enhanced score = `(severity × exploitability × confidence) + vector_similarity_boost` where similar CVEs with known exploits get priority.
- **Precedent-based patches**: Query Redis VL for "closest matching fix pattern" based on embeddings of past code patches (GitHub-scraped via BrightData or curated).

#### **Vector-Enhanced PR Generation**
- **Context retrieval**: For each finding, query Redis VL to get:
  - Similar vulnerability patterns and their proven fixes
  - Code diff examples from successful security patches
  - Framework-specific remediation patterns (e.g., Express.js SQL injection → parameterized queries)
- **Grounded patch synthesis**: LlamaIndex query engine combines current code context + vector-retrieved patch patterns to generate contextual fixes.
- **Open PRs**: Use GitHub API (`PyGithub`) to create branch `fix/<finding_id>`, commit diff, open PR; tag `human_review_required: true` with vector confidence scores.

#### **Enhanced Prompt Template**
```text
Context: Found {{vulnerability_type}} in {{file_path}} (line {{line_number}})
Similar fixes from vector DB: {{vector_matches}}
Proven patch patterns: {{patch_examples}}

Generate a security patch that:
- Addresses the specific {{vulnerability_type}} using proven patterns from similar fixes
- Follows {{language}}/{{framework}} security best practices from vector database
- Includes proper input validation/sanitization based on retrieved examples
- Adds configuration/documentation updates as shown in similar patches
- Provides unit tests that verify the security fix

Return: unified diff patch + PR body with vector confidence score
```

### Hour 3:30 → 4:00 — Verifier Agent with Vector Validation
- **Vector-validated fixes**: After PR merge, embed the applied patch and query Redis VL to confirm it matches known successful vulnerability remediations.
- **Simulated PRs**: Merge, rerun deterministic scanner; findings should be resolved with vector confidence score improvement.
- **NodeZero**: If used, rerun targeted checks or the asset scan via GraphQL and confirm findings cleared; compare vector similarity scores before/after.
- **Intelligence metrics**: log `findings_before`, `findings_after`, `avg_severity_reduced`, `vector_confidence_improvements`, `patch_effectiveness_score`.

### Hour 4:00 → 5:00 — Polish + Demo
- **Minimal UI/CLI**: A small FastAPI or terminal script that:
  - starts job: `scan <target>`
  - streams events: `[SCOUT]`, `[PENTEST]`, `[TRIAGE]`, `[PR_OPENED]`, `[VERIFY]`
  - on PR open: show diff summary and PR URL
- **Tracing/logging**: simple JSON logs with agent names and timestamps.
- **Safety slide**: “All scans targeted demo repo/site only. No external assets tested.”

## Vector Similarity Architecture Overview

### **Redis Vector Similarity as Core Intelligence Layer**
The enhanced architecture positions Redis VL as the central threat intelligence retrieval system:

1. **Knowledge Base Population** (Scout Agent)
   - Scrape vulnerability feeds, CVE databases, exploit repositories via BrightData MCP
   - Embed vulnerability descriptions, patch diffs, remediation patterns using OpenAI embeddings
   - Store in multiple Redis indices: `vulnerabilities`, `patches`, `exploits`, `codebase_patterns`

2. **Contextual Vulnerability Detection** (Pentest Agent)
   - For each detected issue, embed the finding description
   - Query Redis VL for semantically similar known vulnerabilities
   - Enrich findings with CVE context, CVSS scores, exploit availability

3. **Precedent-Based Remediation** (Triage Agent)
   - Embed current code context + vulnerability pattern
   - Vector search for "closest matching fix pattern" from historical patches
   - Generate PRs grounded in proven remediation precedents, not naive fixes

4. **Validation Through Similarity** (Verifier Agent)
   - Embed applied patches and validate against known successful remediations
   - Vector confidence scoring for patch effectiveness prediction

### **Vector Query Examples**
```python
# Find similar vulnerabilities
similarity_results = vuln_store.similarity_search(
    "SQL injection in Express.js login endpoint", 
    k=5, 
    metadata_filter={"language": "javascript", "framework": "express"}
)

# Find proven patches for specific vulnerability types
patch_patterns = patches_store.similarity_search(
    "parameterized query SQL injection fix", 
    k=3,
    metadata_filter={"vulnerability_type": "sql_injection", "effectiveness": "high"}
)
```

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
