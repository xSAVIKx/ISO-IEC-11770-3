from key_derivation.IEEE_P1363 import derivate_key

__author__ = 'Iurii Sergiichuk'


def test_derivate_key():
    shared_secret = 0
    str_shared_secret = str(shared_secret)
    key_derivation_parameters = []
    key_derivation_parameters.append('param1')
    key_derivation_parameters.append('param2')
    result = derivate_key(str_shared_secret, *key_derivation_parameters)
    assert result == 'f56135908c2e0ab5a0b32e5d3b55402f52b98d5e3650414680a9c870bc2eb6435454574e9247a265d975459b8a41df6a8ec321ac5217d3fd9afce42f151294b2'


if __name__ == "__main__":
    test_derivate_key()