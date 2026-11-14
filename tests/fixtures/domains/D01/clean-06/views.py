import markupsafe

def bio(text):
    return markupsafe.escape(text)
