# ruff: noqa: E501
"""Generate the synthetic M3 domain fixtures (D-63): 10 vulnerable and 10 clean projects per domain.

Every fixture is synthetic and non-malicious. No code is ever run, and no credential is real.
Vulnerable fixtures declare, **before any measurement**, the issues they contain and the checks designed
to detect each one (`expected.json`, "any_of"). Clean fixtures declare no issues. Expectations are
never edited to match scanner output.

Usage: python scripts/m3/make_fixtures.py [--out tests/fixtures/domains]
"""

from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
S = "semgrep:semgrep."


def exp(eid: str, file: str, *checks: str) -> dict[str, object]:
    return {"id": eid, "file": file, "any_of": list(checks)}


# Each entry: (files {path: text}, expected [...])
D01_VULN = [
    (
        {"static/app.js": "function show(m){ document.getElementById('o').innerHTML = m; }\n"},
        [exp("dom-xss-innerhtml", "static/app.js", S + "sentinel-web-innerhtml-assignment")],
    ),
    (
        {"static/a.js": "function swap(el, h){ el.outerHTML = h; }\n"},
        [exp("dom-xss-outerhtml", "static/a.js", S + "sentinel-web-innerhtml-assignment")],
    ),
    (
        {"static/w.js": "function log(q){ document.write(q); }\n"},
        [exp("dom-xss-document-write", "static/w.js", S + "sentinel-web-document-write")],
    ),
    (
        {
            "src/Comment.jsx": "export const C = ({html}) => <div dangerouslySetInnerHTML={{__html: html}} />;\n"
        },
        [exp("react-raw-html", "src/Comment.jsx", S + "sentinel-web-react-dangerous-html")],
    ),
    (
        {
            "app.py": "import flask\napp = flask.Flask(__name__)\n\n@app.route('/hi')\ndef hi():\n    return flask.render_template_string(flask.request.args.get('t'))\n"
        },
        [exp("ssti", "app.py", S + "sentinel-web-flask-template-string")],
    ),
    (
        {"views.py": "import markupsafe\n\ndef bio(text):\n    return markupsafe.Markup(text)\n"},
        [exp("markup-unescaped", "views.py", S + "sentinel-web-markup-unescaped")],
    ),
    (
        {
            "nav.py": "import flask\napp = flask.Flask(__name__)\n\n@app.route('/go')\ndef go():\n    return flask.redirect(flask.request.args.get('next'))\n"
        },
        [exp("open-redirect", "nav.py", S + "sentinel-web-open-redirect")],
    ),
    (
        {"templates/profile.html": "<p>{{ user.bio | safe }}</p>\n"},
        [exp("template-safe", "templates/profile.html", S + "sentinel-web-template-safe-filter")],
    ),
    (
        {"static/calc.js": "function run(expr){ return eval(expr); }\n"},
        [exp("js-eval", "static/calc.js", S + "sentinel-js-eval")],
    ),
    (
        {
            "static/feed.js": "function render(items, el){ el.innerHTML = items.join(''); document.write(items[0]); }\n"
        },
        [
            exp("dom-xss-innerhtml-2", "static/feed.js", S + "sentinel-web-innerhtml-assignment"),
            exp("dom-xss-document-write-2", "static/feed.js", S + "sentinel-web-document-write"),
        ],
    ),
]
D01_CLEAN = [
    {"static/app.js": "function show(m){ document.getElementById('o').textContent = m; }\n"},
    {"static/a.js": "function set(el){ el.innerHTML = '<b>static</b>'; }\n"},
    {"static/w.js": "function hello(){ document.write('hello'); }\n"},
    {"src/Comment.jsx": "export const C = ({text}) => <div>{text}</div>;\n"},
    {
        "app.py": "import flask\napp = flask.Flask(__name__)\n\n@app.route('/hi')\ndef hi():\n    return flask.render_template('hi.html', name=flask.request.args.get('n'))\n"
    },
    {"views.py": "import markupsafe\n\ndef bio(text):\n    return markupsafe.escape(text)\n"},
    {
        "nav.py": "import flask\napp = flask.Flask(__name__)\n\n@app.route('/go')\ndef go():\n    return flask.redirect(flask.url_for('home'))\n"
    },
    {"templates/profile.html": "<p>{{ user.bio }}</p>\n"},
    {"static/calc.js": "function run(a, b){ return Number(a) + Number(b); }\n"},
    {
        "static/feed.js": "function render(items, el){ for (const i of items){ const li = document.createElement('li'); li.textContent = i; el.appendChild(li); } }\n"
    },
]

D02_VULN = [
    (
        {
            "auth.py": "import jwt\n\ndef user(token):\n    return jwt.decode(token, options={'verify_signature': False})\n"
        },
        [exp("jwt-unverified", "auth.py", S + "sentinel-api-jwt-signature-not-verified")],
    ),
    (
        {
            "auth2.py": "import jwt\n\ndef user(token, key):\n    return jwt.decode(token, key, verify=False)\n"
        },
        [exp("jwt-verify-false", "auth2.py", S + "sentinel-api-jwt-signature-not-verified")],
    ),
    (
        {
            "api.py": "import flask, flask_cors\napp = flask.Flask(__name__)\nflask_cors.CORS(app, origins='*', supports_credentials=True)\n"
        },
        [exp("cors-wildcard-creds", "api.py", S + "sentinel-api-cors-wildcard-with-credentials")],
    ),
    (
        {
            "server.js": "const cors = require('cors');\nconst app = require('express')();\napp.use(cors({ origin: '*', credentials: true }));\n"
        },
        [
            exp(
                "express-cors-wildcard-creds",
                "server.js",
                S + "sentinel-api-express-cors-wildcard-credentials",
            )
        ],
    ),
    (
        {
            "main.py": "import flask\napp = flask.Flask(__name__)\n\nif __name__ == '__main__':\n    app.run(host='0.0.0.0', debug=True)\n"
        },
        [exp("debug-server", "main.py", S + "sentinel-api-debug-server")],
    ),
    (
        {
            "users.py": "import flask\nfrom models import User\napp = flask.Flask(__name__)\n\n@app.post('/u')\ndef create():\n    return User(**flask.request.json)\n"
        },
        [exp("mass-assignment", "users.py", S + "sentinel-api-mass-assignment")],
    ),
    (
        {
            "tok.py": "import jwt\n\ndef read(t, k):\n    return jwt.decode(t, k, algorithms=['HS256', 'none'])\n"
        },
        [exp("jwt-none-alg", "tok.py", S + "sentinel-api-jwt-none-algorithm")],
    ),
    (
        {"client.py": "import requests\n\ndef fetch(u):\n    return requests.get(u, verify=False)\n"},
        [exp("tls-verify-disabled", "client.py", S + "sentinel-python-tls-verify-disabled")],
    ),
    (
        {
            "orders.py": "import flask\nfrom models import Order\napp = flask.Flask(__name__)\n\n@app.post('/o')\ndef new():\n    return Order(**flask.request.get_json())\n"
        },
        [exp("mass-assignment-2", "orders.py", S + "sentinel-api-mass-assignment")],
    ),
    (
        {
            "gw.py": "import jwt, flask\napp = flask.Flask(__name__)\n\ndef claims(t):\n    return jwt.decode(t, options={'verify_signature': False})\n\nif __name__ == '__main__':\n    app.run(debug=True)\n"
        },
        [
            exp("jwt-unverified-2", "gw.py", S + "sentinel-api-jwt-signature-not-verified"),
            exp("debug-server-2", "gw.py", S + "sentinel-api-debug-server"),
        ],
    ),
]
D02_CLEAN = [
    {
        "auth.py": "import jwt\n\ndef user(token, key):\n    return jwt.decode(token, key, algorithms=['HS256'])\n"
    },
    {
        "auth2.py": "import jwt\n\ndef user(token, key):\n    return jwt.decode(token, key, algorithms=['RS256'], audience='api')\n"
    },
    {
        "api.py": "import flask, flask_cors\napp = flask.Flask(__name__)\nflask_cors.CORS(app, origins=['https://app.example.org'], supports_credentials=True)\n"
    },
    {
        "server.js": "const cors = require('cors');\nconst app = require('express')();\napp.use(cors({ origin: 'https://app.example.org', credentials: true }));\n"
    },
    {
        "main.py": "import flask, os\napp = flask.Flask(__name__)\n\nif __name__ == '__main__':\n    app.run(host='127.0.0.1', debug=False)\n"
    },
    {
        "users.py": "import flask\nfrom models import User\napp = flask.Flask(__name__)\n\n@app.post('/u')\ndef create():\n    d = flask.request.json\n    return User(name=d['name'])\n"
    },
    {"tok.py": "import jwt\n\ndef read(t, k):\n    return jwt.decode(t, k, algorithms=['HS256'])\n"},
    {"client.py": "import requests\n\ndef fetch(u):\n    return requests.get(u, timeout=10)\n"},
    {
        "orders.py": "import flask\nfrom models import Order\napp = flask.Flask(__name__)\n\n@app.post('/o')\ndef new():\n    body = flask.request.get_json()\n    return Order(sku=body['sku'], qty=int(body['qty']))\n"
    },
    {"gw.py": "import jwt\n\ndef claims(t, key):\n    return jwt.decode(t, key, algorithms=['ES256'])\n"},
]

REQ_VULN = "requests==2.19.0\nurllib3==1.24.1\nJinja2==2.10\n"
D08_VULN = [
    (
        {
            "fetch.py": "import flask, requests\napp = flask.Flask(__name__)\n\n@app.get('/p')\ndef proxy():\n    return requests.get(flask.request.args.get('url')).text\n"
        },
        [exp("ssrf", "fetch.py", S + "sentinel-backend-ssrf-request-url")],
    ),
    (
        {
            "files.py": "import flask, os\napp = flask.Flask(__name__)\n\n@app.get('/f')\ndef f():\n    return open(os.path.join('/srv/data', flask.request.args.get('name'))).read()\n"
        },
        [exp("path-traversal", "files.py", S + "sentinel-backend-path-traversal")],
    ),
    (
        {"tmp.py": "import tempfile\n\ndef scratch():\n    return tempfile.mktemp()\n"},
        [exp("mktemp", "tmp.py", S + "sentinel-backend-insecure-tempfile")],
    ),
    (
        {
            "settings.py": "import flask\napp = flask.Flask(__name__)\napp.config['SECRET_KEY'] = 'change-me-please'\n"
        },
        [exp("hardcoded-secret-key", "settings.py", S + "sentinel-backend-hardcoded-secret-key")],
    ),
    (
        {
            "xmlin.py": "import lxml.etree\n\ndef parse(b):\n    return lxml.etree.fromstring(b, lxml.etree.XMLParser(resolve_entities=True))\n"
        },
        [exp("xxe", "xmlin.py", S + "sentinel-backend-xml-external-entities")],
    ),
    (
        {
            "srv.js": "const fs = require('fs');\nmodule.exports = (req, res) => res.send(fs.readFileSync(req.query.file));\n"
        },
        [exp("node-path-traversal", "srv.js", S + "sentinel-backend-node-path-traversal")],
    ),
    (
        {
            "jobs.py": "import subprocess, pickle\n\ndef run(cmd, blob):\n    subprocess.run(cmd, shell=True)\n    return pickle.loads(blob)\n"
        },
        [
            exp("shell", "jobs.py", S + "sentinel-python-subprocess-shell"),
            exp("pickle", "jobs.py", S + "sentinel-python-pickle-load"),
        ],
    ),
    (
        {
            "Dockerfile": 'FROM python:3.12-slim\nCOPY . /app\nCMD ["python", "/app/main.py"]\n',
            "main.py": "print('ok')\n",
        },
        [exp("container-root-user", "Dockerfile", "checkov:checkov.CKV_DOCKER_3")],
    ),
    (
        {
            "main.tf": 'resource "aws_security_group" "web" {\n  name = "web"\n  ingress {\n    from_port   = 22\n    to_port     = 22\n    protocol    = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
        },
        [exp("ssh-open-world", "main.tf", "checkov:checkov.CKV_AWS_24")],
    ),
    (
        {"requirements.txt": REQ_VULN, "app.py": "import requests\n"},
        [
            exp("requests-cve-2018-18074", "requirements.txt", "vuln:vuln.CVE-2018-18074"),
            exp("urllib3-cve-2019-11324", "requirements.txt", "vuln:vuln.CVE-2019-11324"),
            exp("jinja2-cve-2019-10906", "requirements.txt", "vuln:vuln.CVE-2019-10906"),
        ],
    ),
]
D08_CLEAN = [
    {
        "fetch.py": "import requests\n\nALLOWED = {'status': 'https://status.example.org/api'}\n\ndef proxy(name):\n    return requests.get(ALLOWED[name], timeout=5).text\n"
    },
    {
        "files.py": "import flask\napp = flask.Flask(__name__)\n\n@app.get('/f')\ndef f():\n    return flask.send_from_directory('/srv/data', 'report.txt')\n"
    },
    {"tmp.py": "import tempfile\n\ndef scratch():\n    fd, path = tempfile.mkstemp()\n    return fd, path\n"},
    {
        "settings.py": "import flask, os\napp = flask.Flask(__name__)\napp.config['SECRET_KEY'] = os.environ['APP_SECRET_KEY']\n"
    },
    {
        "xmlin.py": "import lxml.etree\n\ndef parse(b):\n    return lxml.etree.fromstring(b, lxml.etree.XMLParser(resolve_entities=False, no_network=True))\n"
    },
    {
        "srv.js": "const path = require('path');\nmodule.exports = (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html'));\n"
    },
    {
        "jobs.py": "import subprocess, json\n\ndef run(args, blob):\n    subprocess.run(['/usr/bin/env', *args], check=True)\n    return json.loads(blob)\n"
    },
    {
        "Dockerfile": 'FROM python:3.12-slim\nRUN useradd -m app\nCOPY . /app\nUSER app\nHEALTHCHECK CMD python -c "print(1)"\nCMD ["python", "/app/main.py"]\n',
        "main.py": "print('ok')\n",
    },
    {"service.py": "def handler(event):\n    return {'status': 200, 'body': str(event.get('id', ''))}\n"},
    # Corrected 2026-11-09 after the preliminary run: requests==2.32.4 has a genuine 2026 advisory
    # (CVE-2026-25645) in the pinned database, so it was not a clean fixture. six has no advisories.
    {"requirements.txt": "six==1.17.0\n", "app.py": "import six\n"},
]

D14_VULN = [
    (
        {
            "repo.py": "def find(cur, name):\n    cur.execute(f\"SELECT * FROM users WHERE name = '{name}'\")\n    return cur.fetchall()\n"
        },
        [exp("sql-fstring", "repo.py", S + "sentinel-db-sql-built-from-strings")],
    ),
    (
        {"repo2.py": "def find(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = ' + uid)\n"},
        [exp("sql-concat", "repo2.py", S + "sentinel-db-sql-built-from-strings")],
    ),
    (
        {"repo3.py": "def find(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = %s' % uid)\n"},
        [exp("sql-percent", "repo3.py", S + "sentinel-db-sql-built-from-strings")],
    ),
    (
        {
            "repo4.py": "def find(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = {}'.format(uid))\n"
        },
        [exp("sql-format", "repo4.py", S + "sentinel-db-sql-built-from-strings")],
    ),
    (
        {
            "models.py": "from app.models import Account\n\ndef by_email(email):\n    return Account.objects.raw(f\"SELECT * FROM account WHERE email = '{email}'\")\n"
        },
        [exp("django-raw", "models.py", S + "sentinel-db-django-raw-formatted")],
    ),
    (
        {
            "store.py": "import sqlalchemy\n\ndef q(conn, sku):\n    return conn.execute(sqlalchemy.text(f\"SELECT * FROM items WHERE sku = '{sku}'\"))\n"
        },
        [exp("sqlalchemy-text", "store.py", S + "sentinel-db-sqlalchemy-text-formatted")],
    ),
    (
        {"db.js": "module.exports = (db, id) => db.query('SELECT * FROM t WHERE id = ' + id);\n"},
        [exp("node-sql-concat", "db.js", S + "sentinel-db-node-query-concatenated")],
    ),
    (
        {"search.js": "module.exports = (col, expr) => col.find({ '$where': expr });\n"},
        [exp("mongo-where", "search.js", S + "sentinel-db-mongo-where-operator")],
    ),
    (
        {
            "conn.py": "import psycopg2\n\ndef connect(host):\n    return psycopg2.connect(host=host, dbname='app', sslmode='disable')\n"
        },
        [exp("db-no-tls", "conn.py", S + "sentinel-db-connection-without-tls")],
    ),
    (
        {
            "rds.tf": 'resource "aws_db_instance" "main" {\n  identifier          = "app"\n  engine              = "postgres"\n  instance_class      = "db.t3.micro"\n  allocated_storage   = 20\n  publicly_accessible = true\n  storage_encrypted   = false\n}\n'
        },
        [
            exp("rds-public", "rds.tf", "checkov:checkov.CKV_AWS_17"),
            exp("rds-unencrypted", "rds.tf", "checkov:checkov.CKV_AWS_16"),
        ],
    ),
]
D14_CLEAN = [
    {
        "repo.py": "def find(cur, name):\n    cur.execute('SELECT * FROM users WHERE name = %s', (name,))\n    return cur.fetchall()\n"
    },
    {"repo2.py": "def find(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = ?', (uid,))\n"},
    {"repo3.py": "def count(cur):\n    cur.execute('SELECT count(*) FROM users')\n"},
    {
        "repo4.py": "def find(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = %(id)s', {'id': uid})\n"
    },
    {
        "models.py": "from app.models import Account\n\ndef by_email(email):\n    return Account.objects.filter(email=email)\n"
    },
    {
        "store.py": "import sqlalchemy\n\ndef q(conn, sku):\n    return conn.execute(sqlalchemy.text('SELECT * FROM items WHERE sku = :sku'), {'sku': sku})\n"
    },
    {"db.js": "module.exports = (db, id) => db.query('SELECT * FROM t WHERE id = $1', [id]);\n"},
    {"search.js": "module.exports = (col, name) => col.find({ name: String(name) });\n"},
    {
        "conn.py": "import psycopg2\n\ndef connect(host):\n    return psycopg2.connect(host=host, dbname='app', sslmode='verify-full')\n"
    },
    {"schema.sql": "CREATE TABLE users (id BIGINT PRIMARY KEY, email TEXT NOT NULL UNIQUE);\n"},
]

DOMAINS = {
    "D01": (D01_VULN, D01_CLEAN),
    "D02": (D02_VULN, D02_CLEAN),
    "D08": (D08_VULN, D08_CLEAN),
    "D14": (D14_VULN, D14_CLEAN),
}


def write(out: Path) -> int:
    if out.exists():
        shutil.rmtree(out)
    n = 0
    for dom, (vuln, clean) in DOMAINS.items():
        assert len(vuln) >= 10 and len(clean) >= 10, dom
        for i, (files, expected) in enumerate(vuln, 1):
            d = out / dom / f"vuln-{i:02d}"
            for rel, text in files.items():
                (d / rel).parent.mkdir(parents=True, exist_ok=True)
                (d / rel).write_text(text)
            (d / "expected.json").write_text(
                json.dumps({"domain": dom, "kind": "vulnerable", "expected": expected}, indent=1) + "\n"
            )
            n += 1
        for i, files in enumerate(clean, 1):
            d = out / dom / f"clean-{i:02d}"
            for rel, text in files.items():
                (d / rel).parent.mkdir(parents=True, exist_ok=True)
                (d / rel).write_text(text)
            (d / "expected.json").write_text(
                json.dumps({"domain": dom, "kind": "clean", "expected": []}, indent=1) + "\n"
            )
            n += 1
    return n


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT / "tests" / "fixtures" / "domains")
    print(write(ap.parse_args().out), "fixtures written")
