<h1 align="center">ffuf-auto</h1>

<p align="center">
  <em>Run vhost, subdomain and directory fuzzing in parallel — in one terminal view.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="MIT License">
  <img src="https://img.shields.io/badge/ffuf-required-orange.svg" alt="Requires ffuf">
  <a href="https://github.com/<your-username>/ffuf-auto/actions"><img src="https://github.com/<your-username>/ffuf-auto/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

---

## Why

Early web recon is always the same three commands, run one after another, each in its own tab:

```bash
ffuf -w subs.txt -u http://target/ -H "Host: FUZZ.target"
ffuf -w subs.txt -u http://FUZZ.target/
ffuf -w dirs.txt -u http://target/FUZZ
```

`ffuf-auto` runs all three **concurrently**, streams their hits into a live three-panel TUI, and writes a structured JSON + Markdown report when it's done — so the findings survive after the screen clears.

## Demo

<p align="center">
  <img src="screenshots/demo.gif" alt="ffuf-auto demo" width="900">
</p>

## Features

- **Parallel execution** — vhost, subdomain and directory scans share one screen instead of three tabs
- **Live TUI** — per-panel hit counters, colour-coded status, built with [Rich](https://github.com/Textualize/rich)
- **Reports on disk** — every run produces `results.json` (machine-readable) and `report.md` (pasteable into notes)
- **Real error surfacing** — missing `ffuf`, bad wordlist paths and non-zero exits are reported instead of silently hanging
- **ffuf passthrough** — `-ac`, `-mc`, `-fc`, `-fs`, `-fw`, `-fr`, `-t`, `-rate`, `-timeout`, plus arbitrary flags via `--ffuf-arg`
- **HTTPS and custom ports** — `--scheme https --port 8443`
- **Politeness controls** — `--stagger` and `--rate` to avoid hammering a target with three scans at once
- **Selective scans** — `--scans vhost directory` to skip what you don't need
- **Graceful `Ctrl+C`** — running children are terminated and partial results are still written

## Requirements

- Python 3.9+
- [`ffuf`](https://github.com/ffuf/ffuf) in `$PATH`
- Wordlists — [SecLists](https://github.com/danielmiessler/SecLists) is assumed by default

```bash
# ffuf
go install github.com/ffuf/ffuf/v2@latest   # or: sudo apt install ffuf

# seclists
sudo apt install seclists                   # installs to /usr/share/seclists
```

## Install

```bash
git clone https://github.com/TARYUS36/ffuf-auto.git
cd ffuf-auto
pip install -r requirements.txt
python3 ffuf_auto.py target.htb
```

Or install it as a proper command:

```bash
pip install .
ffuf-auto target.htb
```

## Usage

```bash
# simplest run — all three scans, default wordlists
ffuf-auto target.htb

# let ffuf work out the noise floor itself instead of guessing -fs
ffuf-auto target.htb -ac

# manual size filters, per scan
ffuf-auto target.htb -fsV 400 -fsS 300 -fsD 1234

# https on a non-standard port, only vhost + directory
ffuf-auto target.htb --scheme https --port 8443 --scans vhost directory

# be gentle: 10 threads, 50 req/s, 5s between scan launches
ffuf-auto target.htb -t 10 --rate 50 --stagger 5

# custom wordlists and output location
ffuf-auto target.htb -w ~/lists/subs.txt -W ~/lists/dirs.txt -o ~/loot

# anything else goes straight to ffuf
ffuf-auto target.htb --ffuf-arg -e --ffuf-arg .php,.bak --ffuf-arg -recursion
```

## Options

| Flag | Description | Default |
|---|---|---|
| `host` | Target host, e.g. `target.htb` | *required* |
| `--scheme {http,https}` | URL scheme | `http` |
| `--port` | Target port | scheme default |
| `--scans` | Which scans to run: `vhost`, `subdomain`, `directory` | all |
| `-w`, `--subdomain-wordlist` | Wordlist for vhost + subdomain | SecLists top-5000 |
| `-W`, `--directory-wordlist` | Wordlist for directory brute force | SecLists dir-2.3-medium |
| `-fsV`, `-fsS`, `-fsD` | Response-size filter for vhost / subdomain / directory | — |
| `-ac`, `--auto-calibrate` | Let ffuf auto-calibrate filters | off |
| `-mc`, `-fc`, `-fw`, `-fr` | Match / filter by status, words, regex | ffuf defaults |
| `-t`, `--threads` | ffuf threads per scan | `40` |
| `--rate` | Requests per second per scan (`0` = unlimited) | `0` |
| `--timeout` | ffuf request timeout in seconds | `10` |
| `--stagger` | Seconds to wait between launching each scan | `0` |
| `-o`, `--output-dir` | Where run directories are written | `results/` |
| `--ffuf-arg` | Raw argument passed to ffuf (repeatable) | — |

## Output

Each run creates its own directory so nothing gets overwritten:

```
results/
└── target.htb_20260806-142310/
    ├── results.json
    └── report.md
```

`results.json` keeps the exact commands, per-scan status, every finding (status, size, words, lines, payload) and any captured stderr — enough to reproduce or diff a run later.

## How it works

```
                 ┌──────────────┐
                 │  ffuf-auto   │
                 └──────┬───────┘
        ┌───────────────┼───────────────┐
   [thread 1]       [thread 2]      [thread 3]
   ffuf vhost       ffuf subdom     ffuf dirs
        │  stdout (-json)  │              │
        └───────────────┬──┴──────────────┘
                        ▼
                  result queues
                        ▼
              Rich Live  →  3 panels
                        ▼
            results.json + report.md
```

Each scan runs as a `subprocess` with `-json`, so results are parsed as structured objects rather than scraped from formatted text. `stdout` is parsed on a worker thread, `stderr` is drained separately into a ring buffer and only surfaced when ffuf exits non-zero.

## Roadmap

- [ ] `--resume` from a previous run directory
- [ ] Recursive directory mode with depth control
- [ ] HTML report output
- [ ] Feed discovered vhosts back into a second-pass directory scan

## Legal

This tool is for authorised security testing and CTF practice only. Run it against systems you own or have explicit written permission to test. Unauthorised scanning is illegal in most jurisdictions, and you alone are responsible for how you use it.

## License

MIT — see [LICENSE](LICENSE).

