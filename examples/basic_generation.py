from passgen_core import encryptors, password_generator

pw = password_generator.generate_password(length=20, use_symbols=True)
print("pw:", pw)

hash_ = encryptors.hash_password_argon2(pw)
print("argon2 hash:", hash_)

enc = encryptors.encrypt_with_password("segreto importante", "my master password")
print("encrypted payload:", enc)
dec = encryptors.decrypt_with_password(enc, "my master password")
print("decrypted:", dec)
