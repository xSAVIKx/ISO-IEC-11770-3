import hashlib
from math import ceil

__author__ = 'Iurii Sergiichuk'

'''
A key derivation function based on the key derivation function that is given in the NIST Special Publication 800-56A
We assume that we use SHA-512 hash function
'''
HASH_LEN = 512
MODULO = 2 << 32
MAX_HASH_INPUT = long(2 << 64 - 1).bit_length() << 64


class OtherInput(object):
    def __init__(self, keydatalen, other_info):
        """
        Input for NIST SP 800 56A key derivation function
        :param keydatalen: An integer that indicates the length (in bits) of the secret keying material to be generated
        :type keydatalen: int
        :param other_info: OtherInfo for key derivation
        :type other_info: OtherInfo
        :return: OtherInput initialized object
        :rtype: OtherInput
        """
        self.keydatalen = keydatalen
        self.other_info = other_info


class OtherInfo(object):
    def __init__(self, algorithm_id, counter=0, entity_A_info=None, entity_B_info=None, supp_priv_info=None,
                 supp_pub_info=None):
        """
        :param algorithm_id: unique identifier of used hash algorithm
        :param counter: counter of iteration
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
        result = str(self.algorithm_id)
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


def kdf(Z, other_input):
    """
    Derivate key using NIST SP 800 56A key derivation function
    :param Z: shared secret
    :param other_input: other input of key derivation function
    :type Z: long
    :type other_input: OtherInput
    :return: derivated key in bit-string format
    :rtype :str
    """
    other_info = other_input.other_info
    keydatalen = other_input.keydatalen
    return derivate_key(Z, keydatalen, other_info)
    pass


def derivate_key(Z, keydatalen, other_info):
    """
    :param Z: shared secret as long number
    :param keydatalen: integer that point Z bit length
    :param other_info: possible additional information
    :type Z: long
    :type keydatalen: int
    :type other_info: OtherInfo
    :return: derivated key in bit-string format
    :rtype : str
    """
    reps = int(ceil(keydatalen * 1.0 / HASH_LEN))
    shared_key_bitstring = bin(Z)[2:]
    if reps > MODULO - 1:
        raise ValueError("reps should be less than 2^32-1, but was:" + str(reps))
    other_info.counter = 0x00000001
    input_len = len(str(other_info.counter) + shared_key_bitstring + str(other_info))
    if input_len > MAX_HASH_INPUT:
        raise ValueError(
            "Input cannot be greater than MAX_HASH_INPUT:" + str(MAX_HASH_INPUT) + ", but was:" + str(input_len))
    hash_parts = []
    for i in xrange(reps):
        value_to_hash = str(other_info.counter) + shared_key_bitstring + str(other_info)
        h = hashlib.sha512()
        h.update(value_to_hash)
        hex_digest = h.hexdigest()
        long_digest = long(hex_digest, base=16)
        h_i = bin(long_digest)[2:]
        hash_parts.append(h_i)
        other_info.counter = (other_info.counter + 1) % MODULO
    r = ''
    for i in xrange(len(hash_parts) - 1):
        r += hash_parts[i]
    h_hash = hash_parts[len(hash_parts) - 1]
    if not is_whole(keydatalen * 1.0 / HASH_LEN):
        h_hash = h_hash[:keydatalen % HASH_LEN]
        r += h_hash
    return r
