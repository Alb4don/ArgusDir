### `Overview`

- It enumerates paths on a target, filters out the responses that only look like hits, and keeps what it learns so later scans against the same kind of stack start from a warmer list.

### `Components`

- `ai_dirscan.py` is the engine and the batch interface. Point it at one or more targets, give it a wordlist, and it runs the full discovery pass and prints results.
 
- `argus_console.py` wraps the same engine in an interactive prompt. You scan, probe individual paths, change settings, and ask about findings in plain language while requests go out live.
 
- `argus_triage.py` reads a saved results file and helps you reason about it afterward, away from the target. It assigns a severity to each finding from a fixed rule set and answers questions about the run.

- All three resolve discovery and severity through shared code, so a finding is scored the same way whether you see it live in the console or later in triage.


<img width="1327" height="399" alt="argus front" src="https://github.com/user-attachments/assets/1f311ef8-b52b-4dbc-9e13-763d5bfc3d6e" />

### `Prerequisites`

- Python 3.8 or newer is required, along with `requests`. Colored output is optional and comes from `colorama` when present.

                  pip install -r requirements.txt

### `Usage`

- Run a scan and save the results:

        python3 ai_dirscan.py -u https://example.com -o findings.json

- Work the same target interactively:

        python3 argus_console.py -u https://example.com

- Review a saved run offline:

        python3 argus_triage.py -f findings.json


### `Options`

        -u, --url            target URL(s)
        -l, --list           wordlist file
        -t, --threads        worker threads (default 10)
      --timeout        request timeout in seconds (default 8)
      --retries        transport retries (default 1)
      --delay          base per-request delay (default 0)
      --max-rps        global requests per second cap
      --depth          recursive descent depth (default 0, off)
      --head-first     probe with HEAD, GET only when warranted
      --follow-redirects   follow redirects and crawl discovered links
      --insecure       skip TLS verification
      --allow-private  permit private or internal targets
      --checkpoint     checkpoint file, resumes automatically
      --cache-db       learning store path
      --no-cache       disable the learning store
      -o, --output     write results
      --format         json or csv (default json)

- The console is for working a target by hand while the engine does the requests. It reads a small command vocabulary rather than open conversation, which keeps every instruction unambiguous.
- When you type `check .env`, it probes exactly `.env` and tells you what came back.

      scan <url>          run a discovery pass
      check <path>        probe one path live and judge whether it is real
      set <opt> <value>   threads, depth, timeout, delay, rps, head-first, wordlist
      config              show the current setup
      what's critical     the findings that warrant attention first
      explain <path>      why a finding matters and what to do about it
      what next           suggested order of work
      results             list everything found so far
      export <file>       save findings as json or csv
      quit

  - A live `check` runs through the same calibration as a full scan, so a path matching the server's not found profile is called out as such instead of padding the list.
  - Findings accumulate in the session and export at any point for later review.

### `Offline triage`

- `argus_triage.py` takes the scanner's JSON output, assigns each finding a severity from a fixed rule set, and lets you query the run. Severity comes from the path and the response together.
- Exposed version control metadata, environment files, database dumps, and private keys rank highest because they tend to leak credentials or source outright.
- A 403 or 401 lowers the ranking and is noted as present but access-controlled, which is a prompt to confirm the control actually holds rather than an assumption that it does.
- A 500 is flagged as an error surface worth investigating.

- An optional language layer can rephrase answers conversationally. It stays off by default and never sets severity; it only restates facts the rule engine has already produced.
- Enabling it with `--llm` requires an OpenAI compatible endpoint configured through the `ARGUS_LLM_ENDPOINT`, `ARGUS_LLM_KEY`, and `ARGUS_LLM_MODEL` environment variables.

      -f, --findings   scanner JSON, or - for stdin
      --once       answer one question and exit
      --report     print a full triage report and exit
      --llm        enable the grounded language layer

### `Disclaimer`

- Run this only against systems you own or have explicit written permission to test. This author is not responsible for the improper and unauthorized use of the tool.
