# netwatch
network monitor 

# netwatch
network monitor 

### SIMPLE README, SCROLL DOWN FOR NERDY MF README
Netwatch v7 is a small program that looks for devices on your home Wi‑Fi and sends a message to your Signal app if something new or risky appears. It runs inside Docker and you start it from the command line.

How it works, in plain words
The program asks the network which devices are online.

It checks a few common network doors on each device to see if they are open.

If it finds a new device or a risky open door, it sends a short message to a Signal number you choose.

The program does not save anything to the computer. Everything is forgotten when it stops.

What you need before you start
A computer or virtual machine with Docker installed.

A Signal REST gateway running on the same machine or reachable from the container. This is usually signal-cli-rest.

A Signal phone number for the gateway and the phone numbers that will receive alerts.

The project files netwatch_v7.py, run.sh, Dockerfile, and requirements.txt.

A .env file with your Signal settings. Keep this file private.

Quick setup steps you can follow in Bash
Put the files in a folder  
Save netwatch_v7.py, run.sh, Dockerfile, and requirements.txt into one folder.

Make the wrapper executable

bash
chmod +x run.sh
Create a .env file  
Save this template as .env and edit the numbers. Keep it secret.

env
SIGNAL_NUMBER="+15551234567"
SIGNAL_RECIPIENTS="+15559876543"
SIGNAL_REST_URL="http://127.0.0.1:8080/v1/messages"
NETWATCH_CMD="scan"
SCAN_PROFILE="standard"
Build the Docker image  
Run this in the folder with the Dockerfile.

bash
docker build -t netwatch:v7 .
Run a single scan  
Use the .env file so you do not put secrets on the command line.

bash
docker run --rm --network host --env-file .env netwatch:v7 scan
Test Signal delivery  
This sends a test message to the recipients in your .env.

bash
docker run --rm --network host --env-file .env netwatch:v7 signal-test
Safety rules you must follow
Do not put your Signal number in public places. Keep the .env file private.

Use a dedicated Signal number for automation. Do not use your personal number.

Host network mode gives the container access to your local network. Only use it on a trusted machine.

The program does not keep logs. If you need records, set up a secure logging solution outside this container.

Troubleshooting simple fixes
If the script does nothing, check that signal-cli-rest is running and reachable at the URL in .env.

If no devices are found, try --network host when running the container.

If the test message does not arrive, confirm SIGNAL_NUMBER and SIGNAL_RECIPIENTS are correct and the gateway is registered.

Short glossary
Docker: a tool that runs programs inside small containers.

Signal REST gateway: a small service that lets programs send Signal messages.

Scan: the action of checking which devices are on the network.

Ephemeral: nothing is saved. When the program stops, everything is gone.

---
**NERDY MF README (DETAILED)**
Netwatch v7 is a Python-based, non‑root network monitoring tool packaged to run from Bash inside a Docker container. It performs unprivileged discovery and TCP connect port scans, keeps all state in memory (no persistent logs or databases by default), and sends alerts only via Signal using a local Signal REST gateway (for example, signal-cli-rest). The container runs as a non‑root user and is intended for ephemeral, low‑footprint monitoring.

What this document covers  
This README explains architecture, configuration, deployment options, security tradeoffs, operational practices, troubleshooting, testing and CI guidance, and a list of enhancement ideas. Read it end‑to‑end before deploying in production.

Architecture
Components
netwatch_v7.py — main Python program. Performs discovery, port scanning, risk scoring, alert batching, and Signal REST calls.

run.sh — Bash wrapper used as the container entrypoint so the image can be invoked from Bash or Docker CLI.

Dockerfile — builds a minimal image with Python and nmap installed, creates a non‑root user, and sets the Bash wrapper as the entrypoint.

requirements.txt — Python dependencies (aiohttp, PyYAML).

Signal REST gateway — external service (recommended) that exposes a local HTTP API for sending Signal messages. Netwatch posts JSON to the gateway; the gateway handles the Signal protocol and keys.

Data flow
Netwatch detects subnets (auto‑detect or configured).

It runs an unprivileged nmap -sn ping sweep to discover hosts.

For discovered hosts it runs unprivileged TCP connect port scans (nmap -sT) using a configured port range/profile.

It classifies open ports against a risk table and computes host risk scores.

Alerts are queued in memory, batched, deduplicated with a cooldown, and posted to the Signal REST gateway.

No files are written by default; all state is in memory and lost when the process exits.

Design constraints and rationale
Non‑root: avoids granting raw socket capabilities and reduces attack surface inside the container.

No persistent logs: minimizes forensic traces on the host; suitable for ephemeral monitoring where persistence is undesirable.

Signal‑only alerts: simplifies external dependencies and centralizes alert delivery to a secure messaging channel.

Dockerized: containerization isolates runtime dependencies and simplifies deployment.

Configuration
Sources of configuration
Environment variables: primary mechanism for secrets and runtime overrides (e.g., SIGNAL_NUMBER, SIGNAL_RECIPIENTS, SIGNAL_REST_URL, NETWATCH_CMD).

Optional YAML config: NETWATCH_CONFIG_PATH can point to a YAML file inside the container to override defaults (scan profiles, batching, quiet hours, concurrency).

Command line: the Bash wrapper accepts a command argument (scan, signal-test) and forwards it to the Python program.

Key configuration options
SIGNAL_NUMBER — E.164 phone number registered with the Signal account used by the gateway.

SIGNAL_RECIPIENTS — comma‑separated recipient numbers.

SIGNAL_REST_URL — URL of the local Signal REST gateway (default http://127.0.0.1:8080/v1/messages).

SCAN_PROFILE — quick, standard, or deep (controls port ranges and timing).

SUBNETS — space‑separated list of CIDR subnets to scan; leave empty to auto‑detect.

BATCH_WINDOW_SECONDS, BATCH_MAX_ITEMS — control alert batching.

ALERT_COOLDOWN_SECONDS — deduplication cooldown to avoid repeated alerts.

QUIET_HOURS_START, QUIET_HOURS_END — suppress non‑critical alerts during specified hours.

CONCURRENCY — number of concurrent port probes.

Config validation and defaults
The program validates presence of required environment variables for signal-test and will attempt to send a test message only if SIGNAL_NUMBER and SIGNAL_RECIPIENTS are set.

Defaults are conservative: standard profile, moderate concurrency, and a default Signal REST URL bound to localhost.

Deployment
Build and run (local)
Build:

bash
chmod +x run.sh
docker build -t netwatch:v7 .
Run a single scan:

bash
docker run --rm --network host --env-file .env netwatch:v7 scan
Test Signal connectivity:

bash
docker run --rm --network host --env-file .env netwatch:v7 signal-test
Running on a VM without interactive login
Use cloud‑init, a provisioning script, or orchestration to:

Install Docker.

Copy the project files or pull the image from a registry.

Build the image (if not pulled).

Run the container detached with --network host and --env-file or Docker secrets.

Example cloud‑init snippet (conceptual):

Install Docker.

docker build -t netwatch:v7 /opt/netwatch.

docker run -d --name netwatch_v7 --network host --env-file /opt/netwatch/.env netwatch:v7 scan.

Docker Compose (local dev)
Use docker-compose to run signal-cli-rest and netwatch:v7 on an internal network. Bind the Signal gateway to 127.0.0.1 or an internal compose network and ensure the gateway is not exposed publicly.

Systemd integration
If you prefer systemd, create a unit that runs docker run --rm ... or uses docker-compose to start the container on boot. Keep secrets out of unit files; use environment files with strict permissions or systemd secrets.

Network mode tradeoffs
Host network: required for full LAN discovery; reduces container isolation. Use only on trusted hosts.

Bridge network: safer isolation but limited discovery; useful if you only need to scan reachable hosts or a specific subnet routed to the container.

Security considerations
Secrets management
Never bake secrets into the image. Use one of:

Docker secrets (Swarm) or Kubernetes secrets.

Bind‑mount a file with strict permissions (chmod 600) and set NETWATCH_CONFIG_PATH to it.

Environment variables passed at runtime (less secure; visible via docker inspect).

External secret manager (Vault, AWS Secrets Manager) for production.

Protect the Signal gateway config directory (where signal-cli stores keys) with chmod 700 and run the gateway under a dedicated user.

Signal gateway security
Run signal-cli-rest as a separate service bound to 127.0.0.1 or an internal network.

If you must expose the gateway, protect it with TLS and authentication (mutual TLS or API key).

Use a dedicated Signal number for automation; do not use your personal number.

Container hardening
Run the container as a non‑root user (Dockerfile creates a netwatch user).

Do not grant --cap-add=NET_RAW or NET_ADMIN unless absolutely necessary.

Avoid mounting host sockets (e.g., /var/run/docker.sock) into the container.

Limit container resources (--memory, --cpus) to reduce DoS risk.

Host hardening
If using --network host, harden the host: firewall rules, minimal services, up‑to‑date packages.

Restrict access to the host and to the directory containing .env or secret files.

Logging and privacy tradeoffs
v7 defaults to in‑memory state and no persistent logs. This reduces traces but also removes auditability.

If you require audit trails, implement secure remote logging (TLS, authentication) or mount an encrypted volume for logs.

Treat MAC addresses, hostnames, and device labels as sensitive data.

Supply chain and updates
Pin base image versions and Python dependency versions.

Build images in CI, sign images, and scan with tools like Trivy before deployment.

Verify nmap and other system packages are from trusted repositories.

Failure and fallback
v7 swallows some errors to avoid writing logs. For critical deployments, add a secure fallback channel (email or webhook) or a health check that reports to a monitoring system.

Implement alert rate limiting and batching to avoid accidental floods.

Legal and ethical
Only scan networks you own or have explicit permission to scan.

Do not use Netwatch to probe or attack third‑party networks.

Be mindful of privacy laws and organizational policies when collecting device identifiers.

Operational considerations
Monitoring and health
Add a health endpoint or a lightweight sidecar that reports container liveness to your orchestrator.

Expose Prometheus metrics (scan duration, hosts found, alerts sent) if you plan to run at scale.

Scheduling and frequency
For periodic scans, schedule container runs externally (cron, systemd timer, Kubernetes CronJob) or modify the wrapper to loop with a sleep interval.

Choose scan frequency based on network size and acceptable load. Frequent deep scans can be disruptive.

Resource tuning
Tune CONCURRENCY and SCAN_PROFILE to balance speed and host load.

Use standard profile for routine scans; deep only when necessary.

Backup and recovery
v7 is ephemeral by design. If you need history, implement a secure, encrypted persistence layer (SQLite with sqlcipher or remote DB).

Back up Signal gateway config and keys securely; losing them may require re‑registration.

Incident response
Define procedures for when a critical alert is received: who is notified, how to verify, and how to remediate.

Keep a secure runbook for Signal account recovery and gateway reconfiguration.

Troubleshooting
Common issues and fixes
No Signal messages received

Verify SIGNAL_NUMBER and SIGNAL_RECIPIENTS environment variables.

Confirm the Signal REST gateway is running and reachable at SIGNAL_REST_URL.

Run signal-test to validate connectivity.

No hosts discovered

If not using --network host, the container may not see the LAN. Use host networking or run on a host with direct LAN access.

Ensure nmap is installed in the image (Dockerfile installs it).

Permission errors on host

Ensure the container is not trying to write to a mounted directory with restrictive permissions.

v7 writes nothing by default; if you mounted volumes, check ownership and permissions.

High false positives

Use standard profile and tune port lists. Some services respond intermittently; consider re‑scanning before alerting.

Silent failures

v7 intentionally avoids persistent logs. Use signal-test and run interactively to debug. For production, add a secure, minimal logging sink.

Debugging tips
Run the container interactively to see stdout/stderr:

bash
docker run --rm -it --network host --env-file .env netwatch:v7 scan
Use nmap manually inside the container to validate discovery and scanning behavior.

Test the Signal gateway with curl to confirm the REST API is reachable.

Testing and CI
Unit and integration testing
Unit test parsing, risk scoring, and alert batching logic with pytest and pytest-asyncio.

Integration tests should mock the Signal REST gateway (local HTTP server) to validate payloads and error handling.

Security scanning
Run bandit on Python code and trivy on built images in CI.

Use safety to check Python dependencies for known vulnerabilities.

Reproducible builds
Pin Python dependency versions in requirements.txt.

Pin base image versions in the Dockerfile and consider using image digests in CI.

Enhancements and future ideas
Encrypted persistence: optional SQLite with sqlcipher to store history and cooldowns across restarts.

Signal gateway hardening: mutual TLS and API key authentication between Netwatch and the gateway.

Metrics endpoint: expose Prometheus metrics for scan counts, durations, and alert rates.

Health and readiness probes: HTTP endpoints for orchestrators to check liveness.

Config management: support dynamic config reload via a mounted config file or HTTP API.

Web UI: small, authenticated UI to view recent scans and alerts (bind to localhost only).

Role separation: run Signal gateway in a separate container with its own user and limited network exposure.

Encrypted remote logging: send minimal audit records to a secure remote collector with TLS and authentication.

Adaptive scanning: use passive discovery sources (DHCP leases, router API) to reduce active scanning.

Plugin system: allow custom detectors or alert formatters to be added without modifying core code.

Rate‑limited escalation: escalate critical alerts to a secondary channel if Signal delivery fails repeatedly.

Automated remediation hooks: integrate with orchestration tools to isolate risky hosts automatically (requires careful security review).

Unit and integration test suite: comprehensive tests with CI pipelines and reproducible test fixtures.
