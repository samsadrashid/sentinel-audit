from app.models import Account

def by_email(email):
    return Account.objects.filter(email=email)
