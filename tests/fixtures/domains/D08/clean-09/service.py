def handler(event):
    return {'status': 200, 'body': str(event.get('id', ''))}
