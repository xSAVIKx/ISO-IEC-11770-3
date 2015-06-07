from key_derivation.NIST_SP_800_56A import OtherInput, OtherInfo, kdf

__author__ = 'Iurii Sergiichuk'


def test_derivate_key():
    shared_secret = long(
        'f56135908c2e0ab5a0b32e5d3b55402f52b98d5e3650414680a9c870bc2eb6435454574e9247a265d975459b8a41df6a8ec321ac5217d3fd9afce42f151294b2f56135908c2e0ab5a0b32e5d3b55402f52b98d5e3650414680a9c870',
        16)
    other_info = OtherInfo(algorithm_id=1)
    other_input = OtherInput(keydatalen=shared_secret.bit_length(), other_info=other_info)
    result = kdf(shared_secret, other_input)
    long_res = long(result, base=2)
    hex_str_res = hex(long_res)[2:][:-1]
    assert hex_str_res == 'ef4fcaeed9c527f19651c5b4b89cef0668d7ee059b738f93169c1bb26c81d33d97088f741cb1ccb53c34cf494d985d249f0acf8724518b8dd58056b9ecb7a47fedb1fc8c3929f5c794a4aa6e7a77559813b8f0453b63020118c560ad'


if __name__ == "__main__":
    test_derivate_key()
