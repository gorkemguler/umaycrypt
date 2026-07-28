"""
UmayCrypt - CLI Arayüzü Testleri
"""

from umay.cli import main


def test_cli_encrypt_decrypt_file(tmp_path):
    input_file = tmp_path / "data.txt"
    output_umay = tmp_path / "data.txt.umay"
    restored_file = tmp_path / "data_restored.txt"

    input_file.write_text("Gizli CLI Metni 123", encoding="utf-8")

    # Encrypt
    res_enc = main(["encrypt", "-i", str(input_file), "-o", str(output_umay), "-p", "Pass123!"])
    assert res_enc == 0
    assert output_umay.exists()

    # Decrypt
    res_dec = main(["decrypt", "-i", str(output_umay), "-o", str(restored_file), "-p", "Pass123!"])
    assert res_dec == 0
    assert restored_file.exists()
    assert restored_file.read_text(encoding="utf-8") == "Gizli CLI Metni 123"


def test_cli_encrypt_decrypt_text_subcommand(capsys):
    msg = "Umay Ana Mesajı"
    passw = "PassText2026"

    # encrypt-text (--message flag)
    res_enc = main(["encrypt-text", "-m", msg, "-p", passw])
    assert res_enc == 0
    captured_enc = capsys.readouterr()
    orhun_output = captured_enc.out.strip()
    assert len(orhun_output) > 0

    # decrypt-text (--message flag)
    res_dec = main(["decrypt-text", "-m", orhun_output, "-p", passw])
    assert res_dec == 0
    captured_dec = capsys.readouterr()
    assert captured_dec.out.strip() == msg

    # decrypt-text (direct positional argument without --message)
    res_dec_pos = main(["decrypt-text", orhun_output, "-p", passw])
    assert res_dec_pos == 0
    captured_dec_pos = capsys.readouterr()
    assert captured_dec_pos.out.strip() == msg


def test_cli_wrong_password_returns_exit_code_1(tmp_path):
    input_file = tmp_path / "secret.txt"
    output_umay = tmp_path / "secret.txt.umay"
    input_file.write_text("Gizli içerik", encoding="utf-8")

    main(["encrypt", "-i", str(input_file), "-o", str(output_umay), "-p", "DogruParola"])

    # Yanlış parola ile deşifreleme
    res_dec = main(["decrypt", "-i", str(output_umay), "-p", "YanlisParola"])
    assert res_dec == 1


def test_cli_missing_input_file():
    res = main(["encrypt", "-i", "/non/existent/file.txt", "-p", "Pass123"])
    assert res == 1
