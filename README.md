# SignalTrace Backend

AI-powered log triage tool backend built with FastAPI.

## Quick Start

```bash
# Clone and navigate
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure environment (optional - works without LLM key)
cp .env.example .env
# Edit .env and add your OpenRouter API key if desired

# Run server
uvicorn app.main:app --reload --port 8000
```

Server will be available at `http://localhost:8000`

API documentation: `http://localhost:8000/docs`

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `OPENAI_API_KEY` | OpenRouter API key (optional) | None |
| `OPENAI_BASE_URL` | API endpoint | `https://openrouter.ai/api/v1` |
| `OPENAI_MODEL` | Model to use | `openai/gpt-4o-mini` |
| `DB_PATH` | SQLite database path | `./data/signaltrace.db` |
| `CORS_ORIGINS` | Allowed CORS origins | `http://localhost:5173` |
| `LOG_LEVEL` | Logging level | `INFO` |

## API Endpoints

### POST /api/analyze
Upload and analyze a log file.

```bash
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@sample.log"
```

### GET /api/runs
List recent analysis runs.

```bash
curl http://localhost:8000/api/runs
```

### GET /api/runs/{run_id}
Get run details with incident summary.

```bash
curl http://localhost:8000/api/runs/{run_id}
```

### GET /api/runs/{run_id}/incidents/{incident_id}
Get full incident details with evidence and explanation.

```bash
curl http://localhost:8000/api/runs/{run_id}/incidents/{incident_id}
```

### GET /health
Health check endpoint.

```bash
curl http://localhost:8000/health
```

## Architecture

```
React Frontend → FastAPI Backend → Pipeline Orchestrator
                                   ↓
                        Parse → Group/Rank → Evidence
                                   ↓
                        LLM (OpenRouter) or Fallback
                                   ↓
                        Validation → SQLite → Response
```

## Demo Safety

- **Works offline**: Fallback mode when no LLM key provided
- **Validation**: Strict schema validation with retry logic
- **Error handling**: Graceful degradation, no crashes
- **Logging**: Request IDs and timing for debugging

## Development

The pipeline is modular. To replace parsing/grouping logic:

1. Edit `app/services/pipeline_interfaces.py`
2. Modify `parse_lines()`, `group_and_rank()`, or `build_evidence()`
3. Keep function signatures intact

To customize LLM prompts:

1. Edit `app/services/llm_client.py`
2. Modify the prompt in `explain_incident()`

## License

MIT

