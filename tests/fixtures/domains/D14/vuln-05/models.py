from app.models import Account

def by_email(email):
    return Account.objects.raw(f"SELECT * FROM account WHERE email = '{email}'")
