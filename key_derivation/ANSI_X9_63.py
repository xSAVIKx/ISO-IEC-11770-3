import hashlib
from math import ceil

__author__ = 'Iurii Sergiichuk'

'''
The ANSI X9.63 key derivation function
We assume that we use SHA-512 hash function
'''
HASH_LEN = 512
MAX_INPUT = HASH_LEN * (2 << 32 - 1)


class SharedInfo(object):
    def __init__(self, algorithm_id, counter=0, entityAinfo=None, entityBinfo=None, suppPrivInfo=None,
                 suppPubInfo=None):
        """
        :arg algorithm_id: unique identifier of used hash algorithm
        :arg counter: counter of iteration
        :type algorithm_id: int
        :type counter: int
        :type entityAinfo: long
        :type entityBinfo: long
        :type suppPrivInfo: long
        :type suppPubInfo: long
        :rtype : SharedInfo
        """
        self.algorithm_id = algorithm_id
        self.counter = counter
        self.entityAinfo = entityAinfo
        self.entityBinfo = entityBinfo
        self.suppPrivInfo = suppPrivInfo
        self.suppPubInfo = suppPubInfo

    def __str__(self):
        result = str(self.algorithm_id) + str(self.counter)
        if self.entityAinfo is not None:
            result += bin(self.entityAinfo)[2:]
        if self.entityBinfo is not None:
            result += bin(self.entityBinfo)[2:]
        if self.suppPrivInfo is not None:
            result += bin(self.suppPrivInfo)[2:]
        if self.suppPubInfo is not None:
            result += bin(self.suppPubInfo)[2:]
        return result


def is_whole(number):
    '''
    Check whether given number is whole or not
    :param number: number to check
    :type number: number
    :return: true, if given number is whole
    :rtype: bool
    '''
    if number % 1 == 0:
        return True
    return False


def derivate_key(Z, keydatalen, shared_info):
    """
    Process key derivation
    :arg Z: shared secret as long number
    :arg keydatalen: integer that point ZZ bit length
    :arg shared_info: possible additional information
    :type Z: long
    :type keydatalen: int
    :type SharedInfo: SharedInfo
    :return: derivated key in bit-string format
    :rtype : str
    """
    if keydatalen > MAX_INPUT:
        raise ValueError("Keydatalen should be less than HASH_LEN*(2^32-1), but was:" + str(keydatalen))
    shared_info.counter = 0x00000001
    hash_parts = []
    for i in xrange(int(ceil(keydatalen * 1.0 / HASH_LEN))):
        value_to_hash = bin(Z)[2:]
        value_to_hash += str(shared_info)
        h = hashlib.sha512()
        h.update(value_to_hash)
        hex_digest = h.hexdigest()
        long_digest = long(hex_digest, base=16)
        h_i = bin(long_digest)[2:]
        hash_parts.append(h_i)
        shared_info.counter += 1
    r = ''
    for i in xrange(len(hash_parts) - 1):
        r += hash_parts[i]
    h_hash = hash_parts[len(hash_parts) - 1]
    if not is_whole(keydatalen * 1.0 / HASH_LEN):
        h_hash = h_hash[:keydatalen - HASH_LEN * (len(hash_parts) - 1)]
    r += h_hash
    return r
