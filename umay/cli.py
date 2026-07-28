"""
UmayCrypt - Komut Satırı Arayüzü (CLI) Modülü

Kullanım Örnekleri:
-------------------
1. Dosya veya Klasör Şifreleme:
   umay encrypt --input gizli.png --output gizli.png.umay
   umay encrypt -i ./belgeler -o belgeler.umay

2. Dosya veya Klasör Deşifre Etme:
   umay decrypt --input gizli.png.umay --output gizli.png
   umay decrypt -i belgeler.umay -o ./belgeler_cozulen

3. Metin Şifreleme (Terminal Çıktısı):
   umay encrypt-text --message "Gizli Mesaj"

4. Metin Deşifre Etme:
   umay decrypt-text --input orhun_metni.umay
   umay decrypt-text --message "𐰉𐰥𐰊..."
"""

import sys
import os
import argparse
import getpass
from typing import Optional

from umay.core import (
    encrypt_data,
    decrypt_data,
    archive_directory,
    unpack_directory,
    is_zip_bytes,
    UmayError,
    UmayCryptoError,
    UmayFileError,
)

# Terminal renk kodları (ANSI)
COLOR_CYAN = "\033[96m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_BOLD = "\033[1m"
COLOR_RESET = "\033[0m"

BANNER = r""" _   _ __  __    _   \ \ / /  ____ ____  \ \ / / ____ _____ 
| | | |  \/  |  / \   \ V /  / ___|  _ \  \ V /|  _ \_   _|
| | | | |\/| | / _ \   | |  | |   | |_) |  | | | |_) || |  
| |_| | |  | |/ ___ \  | |  | |___|  _ <   | | |  __/ | |  
 \___/|_|  |_/_/   \_\ |_|   \____|_| \_\  |_| |_|    |_|  
"""

BANNER_COLOR = f"{COLOR_CYAN}{COLOR_BOLD}{BANNER}{COLOR_RESET}{COLOR_YELLOW}    --- Umay Ana'nın Koruması Altında Veri Şifreleme ---{COLOR_RESET}\n"


def _print_banner():
    """Terminalde UmayCrypt başlığını gösterir."""
    if sys.stdout.isatty():
        print(BANNER_COLOR, file=sys.stderr)


def _get_password(prompt_confirm: bool = False, provided_password: Optional[str] = None) -> str:
    """
    Parolayı getpass ile gizli olarak alır.
    Şifreleme aşamasında (prompt_confirm=True) parolayı iki kere isteyip doğrular.

    :param prompt_confirm: Parola doğrulama istensin mi?
    :param provided_password: Testler/otomasyon için doğrudan verilen parola (varsa).
    :return: Parola metni.
    """
    if provided_password:
        return provided_password

    if not sys.stdin.isatty():
        # Pipe/stdin durumunda satır okuma
        pwd = sys.stdin.readline().rstrip("\r\n")
        if not pwd:
            raise UmayCryptoError("Girdi akışından parola okunamadı.")
        return pwd

    prompt_msg = f"{COLOR_BOLD}{COLOR_CYAN}🛡️  Anahtar Parolanızı Girin: {COLOR_RESET}"
    pwd = getpass.getpass(prompt_msg)
    if not pwd:
        raise UmayCryptoError("Parola boş bırakılamaz.")

    if prompt_confirm:
        confirm_msg = f"{COLOR_BOLD}{COLOR_CYAN}🛡️  Parolanızı Tekrar Girin: {COLOR_RESET}"
        pwd_confirm = getpass.getpass(confirm_msg)
        if pwd != pwd_confirm:
            raise UmayCryptoError("Parolalar birbiriyle eşleşmiyor!")

    return pwd


def handle_encrypt(args: argparse.Namespace) -> int:
    """umay encrypt komutu işleyicisi."""
    input_path = args.input
    if not os.path.exists(input_path):
        print(f"{COLOR_RED}❌ Hata: Girdi dosyası veya klasörü bulunamadı: {input_path}{COLOR_RESET}", file=sys.stderr)
        return 1

    # Çıktı yolu belirleme
    output_path = args.output
    if not output_path:
        if os.path.isdir(input_path):
            output_path = input_path.rstrip("/\\") + ".umay"
        else:
            output_path = input_path + ".umay"

    try:
        password = _get_password(prompt_confirm=True, provided_password=args.password)

        if os.path.isdir(input_path):
            print(f"{COLOR_CYAN}📦 Klasör arşivleniyor: {input_path}{COLOR_RESET}", file=sys.stderr)
            raw_bytes = archive_directory(input_path)
        else:
            print(f"{COLOR_CYAN}📄 Dosya okunuyor: {input_path}{COLOR_RESET}", file=sys.stderr)
            with open(input_path, "rb") as f:
                raw_bytes = f.read()

        print(f"{COLOR_YELLOW}🔐 AES-256-GCM + Argon2id ile şifreleniyor & Orhun motifine işleniyor...{COLOR_RESET}", file=sys.stderr)
        orhun_text = encrypt_data(raw_bytes, password)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(orhun_text)

        print(f"{COLOR_GREEN}✨ Başarılı! Veri Umay Ana'nın koruması altında mühürlendi.{COLOR_RESET}", file=sys.stderr)
        print(f"{COLOR_BOLD}📁 Çıktı Dosyası:{COLOR_RESET} {output_path}", file=sys.stderr)
        return 0

    except UmayError as e:
        print(f"{COLOR_RED}❌ Hata: {e}{COLOR_RESET}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"{COLOR_RED}❌ Beklenmeyen Hata: {e}{COLOR_RESET}", file=sys.stderr)
        return 1


def handle_decrypt(args: argparse.Namespace) -> int:
    """umay decrypt komutu işleyicisi."""
    input_path = args.input
    if not os.path.isfile(input_path):
        print(f"{COLOR_RED}❌ Hata: .umay şifreli dosyası bulunamadı: {input_path}{COLOR_RESET}", file=sys.stderr)
        return 1

    try:
        password = _get_password(prompt_confirm=False, provided_password=args.password)

        with open(input_path, "r", encoding="utf-8") as f:
            orhun_text = f.read().strip()

        print(f"{COLOR_YELLOW}🔓 Orhun harfleri çözümleniyor & AES-256-GCM auth_tag doğrulanıyor...{COLOR_RESET}", file=sys.stderr)
        decrypted_bytes = decrypt_data(orhun_text, password)

        output_path = args.output
        if is_zip_bytes(decrypted_bytes):
            # Klasör arşivi açma
            if not output_path:
                if input_path.endswith(".umay"):
                    output_path = input_path[:-5] + "_cozulen"
                else:
                    output_path = input_path + "_cozulen"

            print(f"{COLOR_CYAN}📂 Klasör arşivi ayıklanıyor: {output_path}{COLOR_RESET}", file=sys.stderr)
            unpack_directory(decrypted_bytes, output_path)
            print(f"{COLOR_GREEN}✨ Başarılı! Umay Ana'nın mühürü açıldı. Klasör çıkarıldı:{COLOR_RESET} {output_path}", file=sys.stderr)
        else:
            # Normal tekil dosya
            if not output_path:
                if input_path.endswith(".umay"):
                    output_path = input_path[:-5]
                else:
                    output_path = input_path + ".cozulen"

            with open(output_path, "wb") as f:
                f.write(decrypted_bytes)

            print(f"{COLOR_GREEN}✨ Başarılı! Umay Ana'nın mühürü açıldı. Dosya oluşturuldu:{COLOR_RESET} {output_path}", file=sys.stderr)

        return 0

    except UmayError as e:
        print(f"{COLOR_RED}❌ Hata: {e}{COLOR_RESET}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"{COLOR_RED}❌ Beklenmeyen Hata: {e}{COLOR_RESET}", file=sys.stderr)
        return 1


def handle_encrypt_text(args: argparse.Namespace) -> int:
    """umay encrypt-text komutu işleyicisi."""
    message = args.message
    if message is None:
        if not sys.stdin.isatty():
            message = sys.stdin.read()
        else:
            print(f"{COLOR_YELLOW}Metni girin (Bitirmek için Ctrl+D yapın):{COLOR_RESET}", file=sys.stderr)
            message = sys.stdin.read()

    if not message:
        print(f"{COLOR_RED}❌ Hata: Şifrelenecek metin boş.{COLOR_RESET}", file=sys.stderr)
        return 1

    try:
        password = _get_password(prompt_confirm=True, provided_password=args.password)
        orhun_text = encrypt_data(message.encode("utf-8"), password)

        # Terminale veya stdout'a yaz
        print(orhun_text)
        return 0

    except UmayError as e:
        print(f"{COLOR_RED}❌ Hata: {e}{COLOR_RESET}", file=sys.stderr)
        return 1


def handle_decrypt_text(args: argparse.Namespace) -> int:
    """umay decrypt-text komutu işleyicisi."""
    orhun_text = None

    if args.input:
        if not os.path.isfile(args.input):
            print(f"{COLOR_RED}❌ Hata: Dosya bulunamadı: {args.input}{COLOR_RESET}", file=sys.stderr)
            return 1
        with open(args.input, "r", encoding="utf-8") as f:
            orhun_text = f.read().strip()
    elif args.message:
        orhun_text = args.message
    else:
        if not sys.stdin.isatty():
            orhun_text = sys.stdin.read().strip()
        else:
            print(f"{COLOR_YELLOW}Orhun metnini girin (Bitirmek için Ctrl+D yapın):{COLOR_RESET}", file=sys.stderr)
            orhun_text = sys.stdin.read().strip()

    if not orhun_text:
        print(f"{COLOR_RED}❌ Hata: Deşifre edilecek Orhun metni sağlanmadı.{COLOR_RESET}", file=sys.stderr)
        return 1

    try:
        password = _get_password(prompt_confirm=False, provided_password=args.password)
        decrypted_bytes = decrypt_data(orhun_text, password)

        try:
            plaintext = decrypted_bytes.decode("utf-8")
            print(plaintext)
        except UnicodeDecodeError:
            # Metin değil ikili veri ise stdout'a yaza bas
            sys.stdout.buffer.write(decrypted_bytes)
        return 0

    except UmayError as e:
        print(f"{COLOR_RED}❌ Hata: {e}{COLOR_RESET}", file=sys.stderr)
        return 1


def main(argv: Optional[list[str]] = None) -> int:
    """CLI ana giriş noktası."""
    parser = argparse.ArgumentParser(
        prog="umay",
        description="UmayCrypt - Göktürk (Orhun-Yenisey) Motifli AES-256-GCM Şifreleme Aracı",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="Kullanılabilir komutlar")

    # 1. encrypt
    p_encrypt = subparsers.add_parser("encrypt", help="Dosya veya klasör şifreleme (.umay üretir)")
    p_encrypt.add_argument("--input", "-i", required=True, help="Şifrelenecek dosya veya klasör yolu")
    p_encrypt.add_argument("--output", "-o", help="Oluşturulacak .umay dosya yolu")
    p_encrypt.add_argument("--password", "-p", help="Şifreleme parolası (Opsiyonel, verilmezse getpass ile istenir)")

    # 2. decrypt
    p_decrypt = subparsers.add_parser("decrypt", help="Şifreli .umay dosyasını veya klasörünü deşifre etme")
    p_decrypt.add_argument("--input", "-i", required=True, help="Deşifre edilecek .umay dosya yolu")
    p_decrypt.add_argument("--output", "-o", help="Çıkarılacak hedef dosya veya klasör yolu")
    p_decrypt.add_argument("--password", "-p", help="Deşifreleme parolası (Opsiyonel, verilmezse getpass ile istenir)")

    # 3. encrypt-text
    p_enc_text = subparsers.add_parser("encrypt-text", help="Düz metni şifreleyip terminale Orhun harfleriyle basma")
    p_enc_text.add_argument("--message", "-m", help="Şifrelenecek düz metin")
    p_enc_text.add_argument("--password", "-p", help="Şifreleme parolası")

    # 4. decrypt-text
    p_dec_text = subparsers.add_parser("decrypt-text", help="Orhun harfli metni deşifre edip terminale basma")
    p_dec_text.add_argument("--input", "-i", help="Orhun metnini içeren dosya")
    p_dec_text.add_argument("--message", "-m", help="Orhun metni dizgisi")
    p_dec_text.add_argument("--password", "-p", help="Deşifreleme parolası")

    args = parser.parse_args(argv)

    if not args.command:
        _print_banner()
        parser.print_help()
        return 0

    if args.command == "encrypt":
        return handle_encrypt(args)
    elif args.command == "decrypt":
        return handle_decrypt(args)
    elif args.command == "encrypt-text":
        return handle_encrypt_text(args)
    elif args.command == "decrypt-text":
        return handle_decrypt_text(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
