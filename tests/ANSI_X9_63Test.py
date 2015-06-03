from key_derivation.ANSI_X9_63 import SharedInfo, derivate_key

__author__ = 'Iurii Sergiichuk'


def test_derivate_key():
    shared_secret = long(
        'f56135908c2e0ab5a0b32e5d3b55402f52b98d5e3650414680a9c870bc2eb6435454574e9247a265d975459b8a41df6a8ec321ac5217d3fd9afce42f151294b2f56135908c2e0ab5a0b32e5d3b55402f52b98d5e3650414680a9c870',
        16)
    bin_shared_secret = bin(shared_secret)[2:]
    other_info = SharedInfo(algorithm_id=1)
    result = derivate_key(shared_secret, len(bin_shared_secret), other_info)
    long_res = long(result, base=2)
    hex_str_res = hex(long_res)[2:][:-1]
    assert hex_str_res == 'e4dcd6f5f7963eaefe33952c63c03b7811ffe78a7efdc280c1a9301a4971037068b8d4c4d66d1a0ebe52ba59fce4fc2b1de63b52cee94547a888fda12478c565accf4b656310122778b0d8eb213f97798a49a913d78375b46878730c'


if __name__ == "__main__":
    test_derivate_key()