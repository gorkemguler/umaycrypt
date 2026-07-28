"""
UmayCrypt - Çekirdek Kriptografi Modülü Testleri
"""

import os
import pytest
from umay.core import (
    encrypt_data,
    decrypt_data,
    archive_directory,
    unpack_directory,
    is_zip_bytes,
    UmayCryptoError,
)

PASSWORD_CORRECT = "UmayAnaKorur2026!"
PASSWORD_WRONG = "YanlisParola123!"


def test_encrypt_decrypt_text_roundtrip():
    plaintext = "Gök Tanrı'nın izni, Umay Ana'nın koruması ile veriler güvende.".encode("utf-8")
    orhun_text = encrypt_data(plaintext, PASSWORD_CORRECT)

    assert isinstance(orhun_text, str)
    assert len(orhun_text) > 0

    decrypted = decrypt_data(orhun_text, PASSWORD_CORRECT)
    assert decrypted == plaintext


def test_wrong_password_fails():
    plaintext = b"Gizli Askeri Belge"
    orhun_text = encrypt_data(plaintext, PASSWORD_CORRECT)

    with pytest.raises(UmayCryptoError, match="başarısız"):
        decrypt_data(orhun_text, PASSWORD_WRONG)


def test_corrupt_ciphertext_fails():
    plaintext = b"Hassas Biyometrik Veri"
    orhun_text = encrypt_data(plaintext, PASSWORD_CORRECT)

    # Bir Orhun harfini değiştirerek veriyi bozuyoruz
    runes = list(orhun_text)
    # 40. harfi değiştir
    runes[40] = chr(0x10C00) if runes[40] != chr(0x10C00) else chr(0x10C01)
    corrupted_orhun = "".join(runes)

    with pytest.raises(UmayCryptoError, match="başarısız"):
        decrypt_data(corrupted_orhun, PASSWORD_CORRECT)


def test_image_file_byte_level_encryption(tmp_path):
    """Büyük resim dosyalarının byte seviyesinde doğru şifrelendiğini ve çözüldüğünü doğrular."""
    # 500 KB'lık rastgele resim baytları simülasyonu
    image_bytes = b"\x89PNG\r\n\x1a\n" + os.urandom(500 * 1024)

    orhun_text = encrypt_data(image_bytes, PASSWORD_CORRECT)
    decrypted_bytes = decrypt_data(orhun_text, PASSWORD_CORRECT)

    assert decrypted_bytes == image_bytes


def test_orhun_mapping_differs_per_password():
    """Aynı verinin farklı parolalarla şifrelendiğinde tamamen farklı Orhun harfleri ürettiğini doğrular."""
    plaintext = b"Sabit Veri Metni 12345"
    pass1 = "ParolaBir_2026"
    pass2 = "ParolaIki_2026"

    orhun1 = encrypt_data(plaintext, pass1)
    orhun2 = encrypt_data(plaintext, pass2)

    # İki harf dizilimi birbirinden tamamen farklı olmalıdır
    assert orhun1 != orhun2
    # İlk 34 harf (başlık) dahi parolaya bağlı olduğu için farklı olmalıdır
    assert orhun1[:34] != orhun2[:34]


def test_directory_archiving_and_decryption(tmp_path):
    """Toplu klasör işleme,zip arşivleme ve geri ayıklamayı doğrular."""
    # Test klasör yapısı oluşturma
    src_dir = tmp_path / "source_folder"
    src_dir.mkdir()
    sub_dir = src_dir / "subfolder"
    sub_dir.mkdir()

    file1 = src_dir / "file1.txt"
    file1.write_text("Metin 1 icerigi", encoding="utf-8")

    file2 = sub_dir / "file2.json"
    file2.write_text('{"key": "value"}', encoding="utf-8")

    # Klasörü zip arşivine çevir ve şifrele
    archived_bytes = archive_directory(str(src_dir))
    assert is_zip_bytes(archived_bytes)

    orhun_text = encrypt_data(archived_bytes, PASSWORD_CORRECT)

    # Deşifre et ve ayıkla
    decrypted_archived = decrypt_data(orhun_text, PASSWORD_CORRECT)
    assert is_zip_bytes(decrypted_archived)

    out_dir = tmp_path / "extracted_folder"
    unpack_directory(decrypted_archived, str(out_dir))

    # İçerikleri kontrol et
    res_file1 = out_dir / "file1.txt"
    res_file2 = out_dir / "subfolder" / "file2.json"

    assert res_file1.exists()
    assert res_file1.read_text(encoding="utf-8") == "Metin 1 icerigi"
    assert res_file2.exists()
    assert res_file2.read_text(encoding="utf-8") == '{"key": "value"}'


def test_empty_password_raises_error():
    with pytest.raises(UmayCryptoError, match="boş"):
        encrypt_data(b"test", "")

    with pytest.raises(UmayCryptoError, match="boş"):
        decrypt_data("𐰀𐰁", "")
