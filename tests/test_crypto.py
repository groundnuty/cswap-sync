import pytest

from cswap_sync.crypto import DecryptError, load_key, new_key, seal, unseal


def test_round_trip(key):
    assert unseal(key, "vm1", seal(key, "vm1", b"logins")) == b"logins"


def test_ciphertext_does_not_contain_the_plaintext(key):
    assert b"refreshToken" not in seal(key, "m", b'{"refreshToken": "x"}')


def test_a_blob_moved_under_another_machine_name_fails(key):
    blob = seal(key, "vm1", b"logins")
    with pytest.raises(DecryptError):
        unseal(key, "vm2", blob)


def test_an_altered_blob_fails(key):
    blob = bytearray(seal(key, "m", b"logins"))
    blob[-1] ^= 1
    with pytest.raises(DecryptError):
        unseal(key, "m", bytes(blob))


def test_another_key_fails(key):
    with pytest.raises(DecryptError):
        unseal(load_key(new_key()), "m", seal(key, "m", b"logins"))


def test_garbage_is_rejected(key):
    with pytest.raises(DecryptError):
        unseal(key, "m", b"not a blob")


@pytest.mark.parametrize("text", ["", "not base64!", "c2hvcnQ="])
def test_bad_keys_are_rejected(text):
    with pytest.raises(ValueError):
        load_key(text)
