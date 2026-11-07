# Local AI Security Log Analyzer

Web app that finds possible attacks in a server log using a **local** LLM (Ollama, CPU only, offline after setup).
The log is larger than the 2,048-token context, so it is split into parts, each part goes to the model in its own call,
facts are carried between calls, and all findings are merged into one final report.

## Setup (Windows / Linux / macOS)
1. Install [Ollama](https://ollama.com) and pull a small model (internet needed once), e.g. `ollama pull qwen3.5:2b`
   (alternatives: `qwen3.5:0.8b`, `gemma4:e2b`; confirm exact tags with `ollama list`).
2. `python -m venv .venv`, activate it, then `pip install -r requirements.txt`
3. PowerShell: `$env:MODEL="qwen3.5:2b"; uvicorn app:app --port 8000`
4. Open http://127.0.0.1:8000, upload `tests/sample.log`, press **Start analysis**.
CPU-only: set `CUDA_VISIBLE_DEVICES=-1` before starting Ollama. Only one call runs at a time.

Env vars: `MODEL`, `OLLAMA_URL`, `LOG_BUDGET` (log tokens per call, default 850), `CALL_TIMEOUT` (seconds, default 240).

## How it works
- **Splitting**: the file is streamed once. Each JSON entry is compacted to one short line
  (`L<line> time app service level ip METHOD path status ...`) keeping the original line number. Entries are never cut.
  A part closes when its estimated token cost reaches `LOG_BUDGET`. Only byte offsets are stored; a part is re-read from disk
  when processed, so no extra copy of the log stays in memory.
- **Token budget per call (2048)**: system prompt ~350, carried facts <= ~250, log text ~850, output cap 400 (`num_predict`), rest is margin.
  Tokens are estimated at 2.6 chars/token (conservative); the real `prompt_eval_count` is shown in the dashboard after each call.
- **Cross-part memory**: a running per-IP table (failed logins, successes, scan paths, SQLi-like requests, rate limiting, injection text, with line ranges)
  is updated each part and sent to the next model call as KNOWN FACTS, so events in different parts can be linked.
- **Merge**: findings are grouped by (attack type, entity), evidence lines are unioned, highest severity wins.
  Every evidence line is checked against the file (line exists and contains the entity); findings without verifiable evidence are dropped.
  Cross-part links computed in code (>= 5 failed logins then a success => Critical *Account Compromise*; injection text => Low *Prompt Injection Attempt*)
  are labelled `cross-part link`; model findings are labelled `model`.
- **Reliability**: one call at a time; retry with back-off; timeout; invalid, binary, empty and oversized uploads rejected;
  tolerant JSON parser (strips fences, trims, salvages complete objects from truncated output); a failed part is recorded and the run continues;
  state is saved to `data/job.json` after every part, so after a restart the page offers **Resume**.
- **Prompt injection**: log text is sent only inside `<LOGS>` delimiters, the system prompt marks it as untrusted data, the output schema is fixed,
  and model output is sanitised (known types, valid severity, checked line numbers). Line 217 of the sample log is a built-in test case.
- **Dashboard**: upload, start/stop/resume, progress bar, per-call timing and tokens, app/system RAM, final report table.

## Known limits
- Small CPU models can miss attacks or over-flag; carried facts and evidence checks reduce this but do not remove it.
- Token count before a call is an estimate (Ollama has no tokenizer endpoint).
- Sample log produces about 12 calls; speed depends on CPU.
- Not done: running several models in one job, authentication, multi-file jobs.
- The 0.8B model missed scanning and the admin export; these are added from the facts carried across parts and are labelled "cross-part link" in the report (model findings are labelled "model").

## Measured on my machine (fill in after your run)
   Model: qwen3.5:0.8b (Ollama), CPU: i5-1135G7 (no GPU), App RAM: ~27 MB (Ollama process RAM: 0.2 MB), Total time: ~2.5 min, Calls: 14, max prompt: 1381 tokens
