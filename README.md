\# CloudJack



\*\*Offline AWS IAM Identity Attack-Path Simulator\*\*



CloudJack is an offline analysis tool that models AWS IAM users, roles, policies, and trust relationships to discover potential privilege escalation paths. It simulates attack routes from a starting identity (e.g., a compromised intern) to a high-value target (e.g., an S3 bucket with production data), scoring the risk, graphing the relationships, and generating least-privilege remediations that close the path.



\## Why CloudJack?



Unlike cloud security scanners that query live AWS APIs (requiring credentials and account access), CloudJack is \*\*entirely offline\*\*. It ingests synthetic JSON snapshots of an IAM environment and builds a mathematical graph of the permissions.



\- \*\*Evidence-first:\*\* Every hop in a path is tagged with the specific policy statement that allows it.

\- \*\*Remediation loop:\*\* It doesn't just find the problem; it generates a remediated JSON file so you can prove the path is closed.

\- \*\*Transparent risk scoring:\*\* We explain exactly how a path scored 85/100 (sensitivity + action severity + path length).

\- \*\*Zero cloud cost:\*\* No real AWS accounts, no leaked credentials, no billing surprises.



\## Safety Boundary



> ⚠️ \*\*Synthetic Data Only.\*\* CloudJack analyses offline JSON snapshots. It does not authenticate to AWS, does not read real credentials, and does not modify infrastructure. All findings are simulated and marked as `policy\_supported` — they are not proof of real-world exploitability.



\## Quick Start



Prerequisite: Python 3.11 or 3.12.



```bash

\# 1. Clone and enter the repository

git clone https://github.com/reallyngb/cloudjack.git

cd cloudjack



\# 2. Create a virtual environment

\# Windows:

py -3.12 -m venv .venv

.venv\\Scripts\\activate

\# macOS/Linux:

\# python3.12 -m venv .venv

\# source .venv/bin/activate



\# 3. Install dependencies and the tool itself

pip install -e ".\[dev]"



\# 4. Run the test suite

pytest -v



\# 5. Run a demonstration scan and generate an HTML report

python -m cloudjack scan --file data/scenarios/multi\_hop\_escalation.json --start "arn:aws:iam::123456789012:user/intern" --target "arn:aws:s3:::prod-data" --report



\# 6. Open the HTML report in your browser

Start-Process report.html

