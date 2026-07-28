"""
UmayCrypt - Göktürk (Orhun-Yenisey) Eşleme Modülü

===============================================================================
ÖNEMLİ KRİPTOGRAFİK AÇIKLAMA VE BİLGİLENDİRME:
-------------------------------------------------------------------------------
Bu modül, şifrelenmiş bayt verilerini Unicode Eski Türkçe (Göktürk / Orhun)
alfabesi karakterlerine dönüştürür ve geri çözer.

GÜVENLİK ROLÜ VE SINIRLARI:
- Bu katman tek başına tam bir şifreleme algoritması DEĞİLDİR.
- Bu katman, AES-256-GCM ile elde edilen authenticated ciphertext baytlarının
  üzerine eklenmiş bir GÖRÜNÜM VE İKİNCİL GİZLEME (Obfuscation) katmanıdır.
- Şifrelenmiş çıktının AES-256-GCM tarafından sağlanan gerçek matematiksel ve
  kriptografik güvenliğini ASLA AZALTMAZ veya ZAYIFLATMAZ.
- Gerçek güvenlik AES-256-GCM (Authenticated Encryption with Associated Data)
  ve Argon2id (Key Derivation Function) tarafından sağlanmaktadır.
- Parolaya bağlı türetilen anahtar (mapping_key) ile Fisher-Yates permütasyonu
  yapılarak 38 Orhun harfinin sırası her parola için farklı üretilir. Bu sayede
  eşleme tablosu da parolasız tahmin edilemez hale getirilir.
===============================================================================
"""

import hashlib
import hmac

class UmayMappingError(Exception):
    """Orhun harf eşleme veya kod çözme hatalarında fırlatılan özel istisna."""
    pass


# Unicode Old Turkic (U+10C00 - U+10C25) bloğundaki 38 temel Orhun harfi
CANONICAL_ORHUN_RUNES: list[str] = [chr(0x10C00 + i) for i in range(38)]

# Harf sayısı doğrulaması
assert len(CANONICAL_ORHUN_RUNES) == 38, "Orhun alfabesi 38 harf olmalıdır."


def generate_permuted_runes(mapping_key: bytes) -> list[str]:
    """
    Argon2id KDF'den türetilen mapping_key kullanarak 38 Orhun harfini
    Fisher-Yates algoritması ile deterministik ancak parolaya özel olarak permüte eder.

    :param mapping_key: Parola ve salt'tan türetilen 32 baytlık anahtar.
    :return: 38 Orhun harfinin karıştırılmış listesi.
    """
    shuffled = list(CANONICAL_ORHUN_RUNES)
    n = len(shuffled)

    # HMAC-SHA256 tabanlı deterministik PRNG üreticisi
    prng_stream = bytearray()
    counter = 0

    def _get_random_bytes(count: int) -> bytes:
        nonlocal counter, prng_stream
        while len(prng_stream) < count:
            # UMAY_MAPPER etiketli HMAC türetimi
            h = hmac.new(
                mapping_key,
                f"UMAY_MAPPER_PERM_V1_{counter}".encode("utf-8"),
                hashlib.sha256
            ).digest()
            prng_stream.extend(h)
            counter += 1
        ret = prng_stream[:count]
        prng_stream = prng_stream[count:]
        return bytes(ret)

    # Fisher-Yates (Knuth) Karıştırma Algoritması
    for i in range(n - 1, 0, -1):
        # 4 baytlık rastgele tamsayı ile modulo sapmasını engelleme
        raw_int = int.from_bytes(_get_random_bytes(4), "big")
        j = raw_int % (i + 1)
        shuffled[i], shuffled[j] = shuffled[j], shuffled[i]

    return shuffled


def encode_bytes_to_orhun(data: bytes, mapping_key: bytes) -> str:
    """
    Girdi baytlarını nibble (4-bit) seviyesinde 2 Orhun harfine dönüştürür.

    Eşleme Şeması Mantığı:
    ----------------------
    1 Bayt = 8 bit = High Nibble (üst 4 bit, 0..15) + Low Nibble (alt 4 bit, 0..15)
    38 harflik permüte diziden:
    - High Nibble (0..15) -> permuted_runes[0..15]
    - Low Nibble  (0..15) -> permuted_runes[16..31]

    Bu ayrım sayesinde üst 4 bit ve alt 4 bit farklı harf kümelerinden seçilir,
    her bayt benzersiz bir 2 Orhun harfi çifti (HighRune + LowRune) olarak temsil edilir.

    :param data: Şifrelenmiş ham bayt dizisi.
    :param mapping_key: Parolaya bağlı eşleme anahtarı.
    :return: Göktürkçe harflerden oluşan metin.
    """
    permuted = generate_permuted_runes(mapping_key)
    high_runes = permuted[0:16]
    low_runes = permuted[16:32]

    orhun_chars = []
    for b in data:
        high_nibble = (b >> 4) & 0x0F
        low_nibble = b & 0x0F
        orhun_chars.append(high_runes[high_nibble])
        orhun_chars.append(low_runes[low_nibble])

    return "".join(orhun_chars)


def decode_orhun_to_bytes(orhun_str: str, mapping_key: bytes) -> bytes:
    """
    Orhun harflerinden oluşan metni tekrar orijinal bayt dizisine dönüştürür.

    :param orhun_str: Göktürkçe harflerden oluşan metin.
    :param mapping_key: Parolaya bağlı eşleme anahtarı.
    :return: Ham bayt dizisi.
    :raises UmayMappingError: Karakterler geçersizse veya uzunluk çift sayı değilse.
    """
    # Orhun metni karakter dizisine ayrıştırılır
    runes_in_str = list(orhun_str.strip())

    if len(runes_in_str) % 2 != 0:
        raise UmayMappingError("Orhun metni bozuk: Harf sayısı çift (2'nin katı) olmalıdır.")

    permuted = generate_permuted_runes(mapping_key)
    high_runes = permuted[0:16]
    low_runes = permuted[16:32]

    # Hızlı ters arama tabloları (High ve Low nibble için)
    high_lookup = {rune: idx for idx, rune in enumerate(high_runes)}
    low_lookup = {rune: idx for idx, rune in enumerate(low_runes)}

    out_bytes = bytearray()
    for i in range(0, len(runes_in_str), 2):
        r_high = runes_in_str[i]
        r_low = runes_in_str[i + 1]

        if r_high not in high_lookup or r_low not in low_lookup:
            raise UmayMappingError("Geçersiz Orhun harfi veya eşleşmeyen parola tablosu.")

        high_val = high_lookup[r_high]
        low_val = low_lookup[r_low]

        byte_val = (high_val << 4) | low_val
        out_bytes.append(byte_val)

    return bytes(out_bytes)
