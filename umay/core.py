"""
UmayCrypt - Çekirdek Kriptografi Modülü (AES-256-GCM + Argon2id)

===============================================================================
GÜVENLİK VE MİMARİ TASARIM:
-------------------------------------------------------------------------------
1. Kriptografik Algoritma: AES-256-GCM (Galois/Counter Mode)
   - Kimlik doğrulamalı şifreleme (Authenticated Encryption with Associated Data - AEAD).
   - Verinin hem GİZLİLİĞİNİ (confidentiality) hem de BÜTÜNLÜĞÜNÜ (integrity) garanti eder.
   - Herhangi bir veri manipülasyonunda veya yanlış parolada auth_tag doğrulaması başarısız olur.

2. Anahtar Türetme Fonksiyonu: Argon2id (OWASP Güvenlik Standartları)
   - Bellek Zorluğu (memory_cost): 65536 KiB (64 MiB) >= OWASP min 19 MiB
   - Zaman Zorluğu (time_cost/iterations): 3 >= OWASP min 2
   - Paralellik (parallelism/lanes): 4
   - Her şifreleme için 16-baytlık (128-bit) cryptographically secure rastgele salt üretilir.
   - KDF çıktısı 64 bayttır: İlk 32 bayt AES-256 anahtarı, son 32 bayt Orhun eşleme anahtarıdır.

3. Dosya / Metin Yapısı (.umay):
   Ham veri yapısı:
   [Versiyon (1B)][Salt (16B)][Nonce (12B)][Auth Tag (16B)][Ciphertext]
   Toplam başlık boyutu = 45 bayt.

4. Zamanlama Saldırılarına Karşı Korumalar:
   - Sabit-zamanlı karşılaştırma için `hmac.compare_digest` kullanılır.
   - Hata mesajları bilgi sızdırmayacak şekilde genel ve net tasarlanmıştır.
===============================================================================
"""

import os
import io
import zipfile
import hmac
from typing import Tuple

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from umay.orhun_mapping import (
    encode_bytes_to_orhun,
    decode_orhun_to_bytes,
    UmayMappingError,
)

# Sabitler
FORMAT_VERSION = 0x01
SALT_SIZE = 16        # 16 bayt (128-bit)
NONCE_SIZE = 12       # 12 bayt (96-bit) AES-GCM nonce
TAG_SIZE = 16         # 16 bayt (128-bit) AES-GCM auth tag
HEADER_SIZE = 1 + SALT_SIZE + NONCE_SIZE + TAG_SIZE  # 45 bayt

# OWASP Tavsiyelerine Uygun Argon2id Parametreleri
ARGON2_MEMORY_COST = 65536  # 64 MiB (KiB cinsinden)
ARGON2_TIME_COST = 3        # İterasyon sayısı
ARGON2_PARALLELISM = 4      # İş parçacığı / lane sayısı
ARGON2_KEY_LEN = 64         # 32B AES Key + 32B Orhun Mapping Key

# Başlık (Salt) Eşleme için Sabit KDF Saltı
HEADER_SALT = b"UMAY_HEADER_SALT_STATIC_V1"
HEADER_BYTES_LEN = 1 + SALT_SIZE  # Versiyon (1B) + Salt (16B) = 17 Bayt -> 34 Orhun Harfi


class UmayError(Exception):
    """UmayCrypt genel istisna sınıfı."""
    pass


class UmayCryptoError(UmayError):
    """Kriptografik doğrulama veya parola hataları için istisna sınıfı."""
    pass


class UmayFileError(UmayError):
    """Dosya okuma/yazma ve arşivleme hataları için istisna sınıfı."""
    pass


def _derive_header_mapping_key(password: str | bytes) -> bytes:
    """
    Başlık (Salt) verisini Orhun harflerine dönüştürmek ve ilk 34 harfi çözmek için
    paroladan sabit bir header saltı ile 32-baytlık eşleme anahtarı türetir.
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password

    kdf = Argon2id(
        salt=HEADER_SALT,
        length=32,
        iterations=2,
        lanes=1,
        memory_cost=19456,  # ~19 MiB
    )
    return kdf.derive(password_bytes)


def derive_keys(password: str | bytes, salt: bytes) -> Tuple[bytes, bytes]:
    """
    Argon2id kullanarak verilen parola ve salt'tan 32 baytlık AES anahtarı
    ve 32 baytlık Orhun eşleme anahtarı türetir.

    :param password: Kullanıcı parolası.
    :param salt: 16 baytlık rastgele salt.
    :return: (aes_key, payload_mapping_key) tüple'ı.
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password

    if len(salt) != SALT_SIZE:
        raise UmayCryptoError("Geçersiz salt boyutu.")

    kdf = Argon2id(
        salt=salt,
        length=ARGON2_KEY_LEN,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST,
    )
    derived = kdf.derive(password_bytes)
    aes_key = derived[:32]
    mapping_key = derived[32:]
    return aes_key, mapping_key


def encrypt_data(data: bytes, password: str | bytes) -> str:
    """
    Ham bayt verisini AES-256-GCM ile şifreler ve parolaya özel üretilmiş
    Orhun (Göktürk) alfabesi harfleriyle kodlanmış metin olarak döndürür.

    :param data: Şifrelenecek ham bayt verisi (metin, resim, arşiv vb.).
    :param password: Kullanıcı parolası.
    :return: Orhun alfabesi karakterlerinden oluşan şifreli metin.
    """
    if not password:
        raise UmayCryptoError("Parola boş olamaz.")

    # 1. Rastgele Salt ve Nonce üretimi
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # 2. Argon2id ile anahtar türetimi
    header_mapping_key = _derive_header_mapping_key(password)
    aes_key, payload_mapping_key = derive_keys(password, salt)

    # 3. AES-256-GCM Şifreleme
    aesgcm = AESGCM(aes_key)
    ct_and_tag = aesgcm.encrypt(nonce, data, None)

    # Ciphertext ve Auth Tag ayrıştırması
    ciphertext = ct_and_tag[:-TAG_SIZE]
    auth_tag = ct_and_tag[-TAG_SIZE:]

    # 4. Ham başlık ve payload paketlemesi
    # Başlık: Versiyon (1B) + Salt (16B) = 17 Bayt
    header_bytes = bytes([FORMAT_VERSION]) + salt
    # Payload: Nonce (12B) + Auth Tag (16B) + Ciphertext
    payload_bytes = nonce + auth_tag + ciphertext

    # 5. Göktürkçe (Orhun) Kodlama Katmanı
    header_orhun = encode_bytes_to_orhun(header_bytes, header_mapping_key)
    payload_orhun = encode_bytes_to_orhun(payload_bytes, payload_mapping_key)

    return header_orhun + payload_orhun


def decrypt_data(orhun_str: str, password: str | bytes) -> bytes:
    """
    Orhun alfabesiyle kodlanmış metni çözer, kimlik doğrulamasını (auth_tag) yapar
    ve orijinal ham bayt verisini döndürür.

    :param orhun_str: Göktürkçe harflerden oluşan şifreli metin.
    :param password: Kullanıcı parolası.
    :return: Deşifre edilmiş ham bayt verisi.
    :raises UmayCryptoError: Parola yanlışsa veya veri bozulmuşsa.
    """
    if not password:
        raise UmayCryptoError("Parola boş olamaz.")

    cleaned_str = orhun_str.strip()
    # 17 Baytlık başlık (Versiyon + Salt) -> 34 Orhun Harfi gerektirir
    min_orhun_len = HEADER_BYTES_LEN * 2  # 34 harf
    if len(cleaned_str) < min_orhun_len:
        raise UmayCryptoError("Şifre çözme başarısız: Veri formatı geçersiz veya eksik.")

    header_orhun = cleaned_str[:min_orhun_len]
    payload_orhun = cleaned_str[min_orhun_len:]

    try:
        # 1. Başlık çözümü ve Salt elde etme
        header_mapping_key = _derive_header_mapping_key(password)
        header_bytes = decode_orhun_to_bytes(header_orhun, header_mapping_key)
    except UmayMappingError:
        raise UmayCryptoError("Şifre çözme başarısız: Parola yanlış veya veri bütünlüğü bozulmuş.")

    version = header_bytes[0]
    # Sabit zamanlı versiyon kontrolü
    if not hmac.compare_digest(bytes([version]), bytes([FORMAT_VERSION])):
        raise UmayCryptoError("Şifre çözme başarısız: Desteklenmeyen dosya versiyonu.")

    salt = header_bytes[1:17]

    try:
        # 2. Argon2id ile anahtarları tekrar türetme
        aes_key, payload_mapping_key = derive_keys(password, salt)

        # 3. Payload kısmını Orhun harflerinden baytlara dönüştürme
        payload_bytes = decode_orhun_to_bytes(payload_orhun, payload_mapping_key)
    except UmayMappingError:
        raise UmayCryptoError("Şifre çözme başarısız: Parola yanlış veya veri bütünlüğü bozulmuş.")

    # Nonce (12B) + Auth Tag (16B) = 28 Bayt minimum payload
    if len(payload_bytes) < (NONCE_SIZE + TAG_SIZE):
        raise UmayCryptoError("Şifre çözme başarısız: Şifreli paket bozuk veya eksik.")

    nonce = payload_bytes[:NONCE_SIZE]
    auth_tag = payload_bytes[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = payload_bytes[NONCE_SIZE + TAG_SIZE:]

    # cryptography AESGCM.decrypt ciphertext + auth_tag bekler
    ct_and_tag = ciphertext + auth_tag

    try:
        # 4. AES-256-GCM Deşifreleme ve Otantikasyon Kontrolü
        aesgcm = AESGCM(aes_key)
        plaintext = aesgcm.decrypt(nonce, ct_and_tag, None)
        return plaintext
    except InvalidTag:
        # Auth tag doğrulaması başarısız oldu — Parola yanlış ya da veri kurcalanmış
        raise UmayCryptoError("Şifre çözme başarısız: Parola yanlış veya veri bütünlüğü bozulmuş.")


def archive_directory(dir_path: str) -> bytes:
    """
    Bir klasörü özyinelemeli (recursive) olarak zip arşiv baytlarına dönüştürür.

    :param dir_path: Şifrelenecek klasör yolu.
    :return: Zip arşivi bayt verisi.
    """
    if not os.path.isdir(dir_path):
        raise UmayFileError(f"Klasör bulunamadı: {dir_path}")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(dir_path):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, dir_path)
                zf.write(full_path, rel_path)

    return buffer.getvalue()


def unpack_directory(zip_data: bytes, output_dir: str) -> None:
    """
    Deşifre edilen zip arşivi baytlarını belirtilen hedefe ayıklar.

    :param zip_data: Deşifre edilmiş zip arşiv baytları.
    :param output_dir: Hedef çıkarılacak klasör.
    """
    os.makedirs(output_dir, exist_ok=True)
    buffer = io.BytesIO(zip_data)
    with zipfile.ZipFile(buffer, "r") as zf:
        zf.extractall(output_dir)


def is_zip_bytes(data: bytes) -> bool:
    """Verinin bir Zip arşivi olup olmadığını sihirli baytlarla (PK\x03\x04) kontrol eder."""
    return data.startswith(b"PK\x03\x04")
