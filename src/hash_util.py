import hashlib
def get_hash(arg: str):
    '''
    Gets hash of a message
    '''
    h = hashlib.new("SHA256")
    h.update(arg.encode())
    return h.hexdigest()
def verify(arg: str, hash_r):
    '''
    Verifies whether the received hash is the correct one
    '''
    if get_hash(arg)==hash_r:
        return True
    return False
