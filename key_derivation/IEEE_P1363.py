import hashlib

__author__ = 'Iurii Sergiichuk'

'''
The IEEE P1363 key derivation function
We assume that we use SHA-512 hash function
'''


def derivate_key(shared_secret, *key_derivation_parameters):
    """
    Key derivation function of IEEE P1363
    :arg shared_secret: shared secret in string format
    :arg key_derivation_parameters: list of possible key derivation parameters in string format
    :type shared_secret: str
    :type key_derivation_parameters: list[str]
    :rtype : str
    """
    value_to_hash = shared_secret
    for arg in key_derivation_parameters:
        value_to_hash += arg
    h = hashlib.sha512()
    h.update(value_to_hash)
    return h.hexdigest()
