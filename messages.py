
def public_key_message(public_key):
    return {
        'type': 'PUBLIC_KEY',
        'data': public_key.decode(),
    }
