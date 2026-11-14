import requests

ALLOWED = {'status': 'https://status.example.org/api'}

def proxy(name):
    return requests.get(ALLOWED[name], timeout=5).text
