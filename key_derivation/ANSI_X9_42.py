import hashlib
from math import floor, ceil
from bitstring import BitArray

__author__ = 'Iurii Sergiichuk'

'''
The ANSI X9.42 key derivation function
'''
HASH_LEN = 512


class OtherInfo(object):
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
        :rtype : OtherInfo
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


def derivate_key(ZZ, keydata_len, other_info):
    """
    :arg ZZ: shared secret as long number
    :arg keydata_len: integer that point ZZ bit length
    :arg other_info: possible additional information
    :type ZZ: long
    :type keydata_len: int
    :type other_info: OtherInfo
    :rtype : str
    """
    d = int(ceil(keydata_len * 1.0 / HASH_LEN))
    other_info.counter = 0x00000001
    hash_parts = ''
    for i in xrange(d):
        value_to_hash = bin(ZZ)[2:]
        value_to_hash += str(other_info)
        h = hashlib.sha512()
        h.update(value_to_hash)
        hex_digest = h.hexdigest()
        int_digest = int(hex_digest, base=16)
        h_i = bin(int_digest)[2:]
        hash_parts += h_i
        other_info.counter += 1
    r = hash_parts[:keydata_len]
    return r