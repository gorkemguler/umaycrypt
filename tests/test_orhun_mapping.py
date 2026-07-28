"""
UmayCrypt - Orhun Eşleme Modülü Testleri
"""

import pytest
from umay.orhun_mapping import (
    generate_permuted_runes,
    encode_bytes_to_orhun,
    decode_orhun_to_bytes,
    CANONICAL_ORHUN_RUNES,
    UmayMappingError,
)

KEY_A = b"01234567890123456789012345678901"
KEY_B = b"98765432109876543210987654321098"


def test_canonical_runes_count():
    assert len(CANONICAL_ORHUN_RUNES) == 38
    assert len(set(CANONICAL_ORHUN_RUNES)) == 38


def test_permuted_runes_uniqueness_and_determinism():
    perm_a1 = generate_permuted_runes(KEY_A)
    perm_a2 = generate_permuted_runes(KEY_A)
    perm_b = generate_permuted_runes(KEY_B)

    # Aynı anahtar aynı sonucu vermeli
    assert perm_a1 == perm_a2
    assert len(perm_a1) == 38
    assert len(set(perm_a1)) == 38

    # Farklı anahtarlar farklı permütasyon üretmeli
    assert perm_a1 != perm_b


def test_encode_decode_roundtrip():
    sample_bytes = b"UmayCrypt Test Data 12345 !@#$%^&*()"
    orhun_str = encode_bytes_to_orhun(sample_bytes, KEY_A)

    # Her 1 bayt 2 Orhun harfine dönüşür
    assert len(orhun_str) == len(sample_bytes) * 2

    decoded = decode_orhun_to_bytes(orhun_str, KEY_A)
    assert decoded == sample_bytes


def test_different_keys_fail_decoding_or_yield_wrong_data():
    sample_bytes = b"Secret Message"
    orhun_str = encode_bytes_to_orhun(sample_bytes, KEY_A)

    # Farklı anahtar ile çözmeye çalışıldığında ya hata vermeli ya da yanlış bayt vermeli
    try:
        decoded = decode_orhun_to_bytes(orhun_str, KEY_B)
        assert decoded != sample_bytes
    except UmayMappingError:
        pass  # Hata vermesi de beklenen bir durumdur


def test_decode_invalid_length():
    with pytest.raises(UmayMappingError, match="çift"):
        decode_orhun_to_bytes("𐰀", KEY_A)  # Tek harf (tek sayı)


def test_decode_invalid_character():
    with pytest.raises(UmayMappingError, match="Geçersiz Orhun"):
        decode_orhun_to_bytes("AB", KEY_A)  # Latin harfleri geçersizdir
