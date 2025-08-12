from core.password_generator import generate_password


def test_length_and_groups():
    p = generate_password(
        length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=False
    )
    assert len(p) == 16
    assert any(c.isupper() for c in p)
    assert any(c.islower() for c in p)
    assert any(c.isdigit() for c in p)
