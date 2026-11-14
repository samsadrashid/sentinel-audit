import subprocess, pickle

def run(cmd, blob):
    subprocess.run(cmd, shell=True)
    return pickle.loads(blob)
