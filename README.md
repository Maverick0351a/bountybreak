# Bounty Workbench

A red team themed local web desk for planning authorized security research and checking one complete workflow in a synthetic lab. The core uses only the Python standard library. There is no account, cloud service, package installation, scanner download, or Docker requirement.

## Run

Requires Python 3.11 or newer.

```sh
python workbench.py
```

Open `http://127.0.0.1:8766/`. Data is saved under `data/` and ignored by Git. To change the location or port:

```sh
python workbench.py --data-dir /private/path --port 8767
```

## Try the complete workflow

1. Create a **Researcher-owned lab** engagement. Use “Bundled synthetic lab” as its authority source. You may record an exact URL or asset identifier now or add more later.
2. Add a hypothesis such as “a member cannot access the admin route” and an impact statement.
3. Click **Run bundled lab check**. The app makes exactly two fixed GET requests to its own temporary loopback lab: `/api/me` and `/api/admin`.
4. Review the saved statuses, response lengths, SHA-256 digests, and negative control. The expected result is HTTP 200 followed by HTTP 403. It demonstrates the workflow, **not a vulnerability**.

The lab server starts on a random loopback port inside the app process and stops with the app. User input cannot change its origin, route, method, request count, or redirect behavior.

## Scope boundary

Bug bounty and internal engagement records are planning only. The app can store URLs and asset identifiers, but does not contact them, accept them as execution targets, run ZAP/Nuclei/ffuf/Shannon, submit reports, or treat a saved plan as authorization. The tool catalog links to official projects for selection and review. Running one of them against a live target would require a separate adapter that enforces current scope, technique permission, identities, request limits, and stop conditions at request time.

The web server binds to `127.0.0.1`, requires a matching Host and Origin plus a session CSRF token for changes, and has no remote access mode. Do not put credentials, session cookies, customer records, or private program text into records. The app stores user-entered fields locally without encryption. Keep the data directory private and out of published commits.

## Optional Shannon path

[Shannon](https://github.com/KeygraphHQ/shannon) is an independent tool. This release records lab plans and evidence but does not install or launch Shannon. A Shannon integration should first use a researcher-owned lab, then add an enforceable per-request scope and budget layer before any live bounty use. Shannon and its runtime are not dependencies of this app.

## Test

```sh
python -m unittest discover -s tests -v
```

The tests cover the end-to-end local run, asset persistence without target traffic, the negative control, and the live-engagement/Host/Origin/CSRF boundary.

## Project status

This is a first working release: local engagement records, hypotheses, a tool catalog, and a bounded synthetic check with sanitized evidence. Public bounty scope import, tool adapters, and Shannon execution are future work. Security findings still require independent reproduction and current program authorization.
