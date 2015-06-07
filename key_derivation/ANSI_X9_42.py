import hashlib
from math import ceil

__author__ = 'Iurii Sergiichuk'

'''
The ANSI X9.42 key derivation function
We assume that we use SHA-512 hash function
'''
HASH_LEN = 512
MAX_INPUT = HASH_LEN * (2 << 32 - 1)


class OtherInfo(object):
    def __init__(self, algorithm_id, counter=0, entity_A_info=None, entity_B_info=None, supp_priv_info=None,
                 supp_pub_info=None):
        """
        :arg algorithm_id: unique identifier of used hash algorithm
        :arg counter: counter of iteration
        :type algorithm_id: int
        :type counter: int
        :type entity_A_info: long
        :type entity_B_info: long
        :type supp_priv_info: long
        :type supp_pub_info: long
        :rtype : OtherInfo
        """
        self.algorithm_id = algorithm_id
        self.counter = counter
        self.entityAinfo = entity_A_info
        self.entityBinfo = entity_B_info
        self.suppPrivInfo = supp_priv_info
        self.suppPubInfo = supp_pub_info

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


def derivate_key(ZZ, keydatalen, other_info):
    """
    :param ZZ: shared secret as long number
    :param keydatalen: integer that point ZZ bit length
    :param other_info: possible additional information
    :type ZZ: long
    :type keydatalen: int
    :type other_info: OtherInfo
    :return: derivated key in bit-string format
    :rtype : str
    """
    if keydatalen > MAX_INPUT:
        raise ValueError("Keydatalen should be less than HASH_LEN*(2^32-1), but was:" + str(keydatalen))
    d = int(ceil(keydatalen * 1.0 / HASH_LEN))
    other_info.counter = 0x00000001
    hash_parts = ''
    for i in xrange(d):
        value_to_hash = bin(ZZ)[2:]
        value_to_hash += str(other_info)
        h = hashlib.sha512()
        h.update(value_to_hash)
        hex_digest = h.hexdigest()
        long_digest = long(hex_digest, base=16)
        h_i = bin(long_digest)[2:]
        hash_parts += h_i
        other_info.counter += 1
    r = hash_parts[:keydatalen]
    return r
