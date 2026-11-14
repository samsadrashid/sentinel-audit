import subprocess, json

def run(args, blob):
    subprocess.run(['/usr/bin/env', *args], check=True)
    return json.loads(blob)
