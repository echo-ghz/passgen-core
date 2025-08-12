from passgen_core import encryptors


def test_argon2_hash_verify():
    h = encryptors.hash_password_argon2("mypw")
    assert encryptors.verify_password_argon2(h, "mypw")


def test_encrypt_decrypt_roundtrip():
    payload = encryptors.encrypt_with_password("hello world", "masterpw")
    assert encryptors.decrypt_with_password(payload, "masterpw") == "hello world"
