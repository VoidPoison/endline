from os import urandom
from tkinter import filedialog as fd
from customtkinter import *
import gostcrypto
from gostcrypto.gostrandom import *
from gostcrypto.gostrandom import R132356510062017

# from datetime import datetime, timedelta
# import ipaddress
# from cryptography import x509
# from cryptography.x509.oid import NameOID
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# from cryptography.hazmat.primitives.asymmetric import rsa

app = CTk()
app.geometry("900x640")
app.title("IDC")
set_appearance_mode("dark")
app.resizable(False, False)


def new(rand_size: int, **kwargs) -> 'R132356510062017':
    rand_k = kwargs.get('rand_k', bytearray(b''))
    size_s = kwargs.get('size_s', SIZE_S_384)
    return R132356510062017(rand_size, rand_k, size_s)


def click_handler_1():
    # Вычисление ХЭШ сообщения
    filename = fd.askopenfilename();
    buffer_size = 128
    hash_obj = gostcrypto.gosthash.new('streebog256')
    with open(filename, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hash_obj.update(buffer)
            buffer = file.read(buffer_size)
    hash_result = hash_obj.hexdigest()
    label_1.configure(text=f"hash: {hash_result}")


def click_handler_2():
    # Выбор файла для вычисления хеш значения
    filename = fd.askopenfilename();
    buffer_size = 128
    hash_obj = gostcrypto.gosthash.new('streebog256')
    with open(filename, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hash_obj.update(buffer)
            buffer = file.read(buffer_size)
    hash_result = hash_obj.hexdigest()
    sk_raw = new(32)
    sk = sk_raw.random()
    sk1 = ''.join(format(x, '02x') for x in sk)
    file = open("key.txt", "w", encoding="utf-8")
    file.write(str(sk1))
    digest = bytearray.fromhex(hash_result)
    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                                'id-tc26-gost-3410-2012-256-paramSetB'])
    sk = bytearray.fromhex(sk1)
    public_key = sign_obj.public_key_generate(sk)
    signature = sign_obj.sign(sk, digest)
    label_2.configure(text=f"finished")

    # Сохранение файла открытого ключа
    openkey = ''.join(format(x, '02x') for x in public_key)
    label_4.configure(text=f"public key: {str(openkey)}")
    filepath = filedialog.asksaveasfilename()
    file = open(filepath, "w", encoding="utf-8")
    file.write(str(openkey))
    file.close()
    # Сохранение файла ЦП
    newsign = ''.join(format(x, '02x') for x in signature)
    filepath = filedialog.asksaveasfilename()
    file = open(filepath, "w", encoding="utf-8")
    file.write(str(newsign))
    file.close()


def click_handler_3():
    #    Выбор файла для вычисления ХЭШа
    filename = fd.askopenfilename();
    buffer_size = 128
    hash_obj = gostcrypto.gosthash.new('streebog256')
    with open(filename, 'rb') as file:
        buffer = file.read(buffer_size)
        while len(buffer) > 0:
            hash_obj.update(buffer)
            buffer = file.read(buffer_size)

    hash_result = hash_obj.hexdigest()
    digest = bytearray.fromhex(hash_result)

    #   Выбор файла с открытым ключом
    filename = fd.askopenfilename()
    with open(filename, 'rt') as file:
        pk = file.read()
        public_key = bytearray.fromhex(pk)

    #   Выбор файла с ЦП
    filename = fd.askopenfilename()
    with open(filename, 'rt') as file:
        sgn = file.read()
        signature = bytearray.fromhex(sgn)

    #    Выбор метода подписи и исходных значений парамертов ЭК,  в расширеной версии существует переключатель исходных значений
    sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                            gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                                'id-tc26-gost-3410-2012-256-paramSetB'])
    if sign_obj.verify(public_key, digest, signature):
        label_3.configure(text=f"Signature is correct")
    else:
        label_3.configure(text=f"Signature is not correct")


# def click_handler_check():
#
#       filename = fd.askopenfilename()
#       with open(filename, 'rt') as file:
#          pk = file.read()
#          public_key = bytearray.fromhex(pk)
#
#       filename = fd.askopenfilename()
#       with open(filename, 'rt') as file:
#          sgn = file.read()
#          signature = bytearray.fromhex(sgn)
#          hostname = "lepexa"
#
#          name = x509.Name([
#             x509.NameAttribute(NameOID.COMMON_NAME, hostname)
#          ])
#          # best practice seem to be to include the hostname in the SAN, which *SHOULD* mean COMMON_NAME is ignored.
#
#          alt_names = [x509.DNSName(hostname)]
#
#          # allow addressing by IP, for when you don't have real DNS (common in most testing scenarios
#          ipaddress = None
#          if ipaddress:
#             for addr in ipaddress:
#                # openssl wants DNSnames for ips...
#                alt_names.append(x509.DNSName(addr))
#                # ... whereas golang's crypto/tls is stricter, and needs IPAddresses
#                # note: older versions of cryptography do not understand ip_address objects
#                alt_names.append(x509.IPAddress(ipaddress.ip_address(addr)))
#
#          san = x509.SubjectAlternativeName(alt_names)
#
#          # path_len=0 means this cert can only sign itself, not other certs.
#          basic_contraints = x509.BasicConstraints(ca=True, path_length=0)
#          now = datetime.utcnow()
#          cert = (
#             x509.CertificateBuilder()
#             .subject_name(name)
#             .issuer_name(name)
#             .public_key(public_key)
#             .serial_number(1000)
#             .not_valid_before(now)
#             .not_valid_after(now + timedelta(days=10 * 365))
#             .add_extension(basic_contraints, False)
#             .add_extension(san, False)
#             .sign(signature)
#          )
#          cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
#          key_pem = key.private_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PrivateFormat.TraditionalOpenSSL,
#             encryption_algorithm=serialization.NoEncryption(),
#          )
#          filepath = filedialog.asksaveasfilename()
#          file = open(filepath, "w", encoding="utf-8")
#          file.write(str(cert_pem))
#          file.close()
#          newsign = ''.join(format(x, '02x') for x in signature)
#          filepath = filedialog.asksaveasfilename()
#          file = open(filepath, "w", encoding="utf-8")
#          file.write(str(key_pem))
#          file.close()


btn_1 = CTkButton(master=app, text="Hash", corner_radius=32, fg_color="transparent",
                  hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_1)
btn_1.place(relx=0.2, rely=0.3, anchor="center")
btn_2 = CTkButton(master=app, text="sign", corner_radius=32, fg_color="transparent",
                  hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_2)
btn_2.place(relx=0.5, rely=0.3, anchor="center")
btn_3 = CTkButton(master=app, text="check", corner_radius=32, fg_color="transparent",
                  hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_3)
btn_3.place(relx=0.8, rely=0.3, anchor="center")

# btn_check = CTkButton(master=app, text="certif", corner_radius=32, fg_color="transparent",
#                 hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_check)
# btn_check.place(relx=1.0, rely=0.5, anchor="center")

label_1 = CTkLabel(master=app, text="", font=("Arial", 20), text_color="#D2691E")
label_1.place(relx=0.5, rely=0.4, anchor="center")
label_4 = CTkLabel(master=app, text="", font=("Arial", 20), text_color="#D2691E")
label_4.place(relx=0.5, rely=0.5, anchor="center")
label_2 = CTkLabel(master=app, text="", font=("Arial", 20), text_color="#D2691E")
label_2.place(relx=0.5, rely=0.6, anchor="center")
label_3 = CTkLabel(master=app, text="", font=("Arial", 20), text_color="#D2691E")
label_3.place(relx=0.5, rely=0.7, anchor="center")

app.mainloop()
