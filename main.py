
from customtkinter import *
import gostcrypto

app = CTk()
app.geometry("500x400")
app.title("IDC")
set_appearance_mode("dark")

def click_handler_1():
   file_path = 'trtr.txt'
   buffer_size = 128
   hash_obj = gostcrypto.gosthash.new('streebog256')
   with open(file_path, 'rb') as file:
      buffer = file.read(buffer_size)
      while len(buffer) > 0:
         hash_obj.update(buffer)
         buffer = file.read(buffer_size)
   hash_result = hash_obj.hexdigest()
   label_1.configure(text=f"hash: {hash_result}")

def click_handler_2():
   file_path = 'trtr.txt'
   buffer_size = 128
   hash_obj = gostcrypto.gosthash.new('streebog256')
   with open(file_path, 'rb') as file:
      buffer = file.read(buffer_size)
      while len(buffer) > 0:
         hash_obj.update(buffer)
         buffer = file.read(buffer_size)
   hash_result = hash_obj.hexdigest()
   private_key = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
   digest = bytearray.fromhex(hash_result)
   sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                           gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                              'id-tc26-gost-3410-2012-256-paramSetB'])
   public_key = bytearray.fromhex('fd21c21ab0dc84c154f3d218e9040bee64fff48bdff814b232295b09d0df72e45026dec9ac4f07061a2a01d7a2307e0659239a82a95862df86041d1458e45049')
   signature = sign_obj.sign(private_key, digest)
   label_2.configure(text=f"finished")
   openkey = ''.join(format(x, '02x') for x in public_key)
   label_4.configure(text=f"public key: {str(openkey)}")
   file = open( "key.txt", "w", encoding="utf-8")
   file.write(str(openkey))
   newsign = ''.join(format(x, '02x') for x in signature)
   file = open("signature.txt", "w", encoding="utf-8")
   file.write(str(openkey))


def click_handler_3():
   file_path = 'trtr.txt'
   buffer_size = 128
   hash_obj = gostcrypto.gosthash.new('streebog256')
   with open(file_path, 'rb') as file:
      buffer = file.read(buffer_size)
      while len(buffer) > 0:
         hash_obj.update(buffer)
         buffer = file.read(buffer_size)

   hash_result = hash_obj.hexdigest()
   digest = bytearray.fromhex(hash_result)
   private_key = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
   sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                           gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                              'id-tc26-gost-3410-2012-256-paramSetB'])
   public_key = bytearray.fromhex('fd21c21ab0dc84c154f3d218e9040bee64fff48bdff814b232295b09d0df72e45026dec9ac4f07061a2a01d7a2307e0659239a82a95862df86041d1458e45049')
   signature = bytearray.fromhex('fd21c21ab0dc84c154f3d218e9040bee64fff48bdff814b232295b09d0df72e45026dec9ac4f07061a2a01d7a2307e0659239a82a95862df86041d1458e45049')
   sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                           gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                              'id-tc26-gost-3410-2012-256-paramSetB'])
   if sign_obj.verify(public_key, digest, signature):
      label_3.configure(text=f"Signature is correct")
   else:
      label_3.configure(text=f"Signature is not correct")

def click_handler_check():
   file_path = 'trtr.txt'
   buffer_size = 128
   hash_obj = gostcrypto.gosthash.new('streebog256')
   with open(file_path, 'rb') as file:
      buffer = file.read(buffer_size)
      while len(buffer) > 0:
         hash_obj.update(buffer)
         buffer = file.read(buffer_size)
   hash_result = hash_obj.hexdigest()
   private_key = bytearray.fromhex('7a929ade789bb9be10ed359dd39a72c11b60961f49397eee1d19ce9891ec3b28')
   digest = bytearray.fromhex(hash_result)
   sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                           gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                              'id-tc26-gost-3410-2012-256-paramSetB'])
   public_key = bytearray.fromhex(
      'fd21c21ab0dc84c154f3d218e9040bee64fff48bdff814b232295b09d0df72e45026dec9ac4f07061a2a01d7a2307e0659239a82a95862df86041d1458e45049')
   signature = sign_obj.sign(private_key, digest)
   label_2.configure(text=f"finished")
   openkey = ''.join(format(x, '02x') for x in public_key)
   label_4.configure(text=f"public key: {str(openkey)}")
   file = open("key.txt", "w", encoding="utf-8")
   file.write(str(openkey))
   newsign = ''.join(format(x, '02x') for x in signature)
   file = open("signature.txt", "w", encoding="utf-8")
   file.write(str(openkey))


   sign_obj = gostcrypto.gostsignature.new(gostcrypto.gostsignature.MODE_256,
                                           gostcrypto.gostsignature.CURVES_R_1323565_1_024_2019[
                                              'id-tc26-gost-3410-2012-256-paramSetB'])
   if sign_obj.verify(public_key, digest, signature):
      label_3.configure(text=f"Signature is correct")
   else:
      label_3.configure(text=f"Signature is not correct")


btn_1 = CTkButton(master=app, text="Hash", corner_radius=32, fg_color="transparent",
                hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_1)
btn_1.place(relx=0.2, rely=0.3, anchor="center")
btn_2 = CTkButton(master=app, text="sign", corner_radius=32, fg_color="transparent",
                hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_2)
btn_2.place(relx=0.5, rely=0.3, anchor="center")
btn_3 = CTkButton(master=app, text="check", corner_radius=32, fg_color="transparent",
                hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_3)
btn_3.place(relx=0.8, rely=0.3, anchor="center")

btn_check = CTkButton(master=app, text="check", corner_radius=32, fg_color="transparent",
                hover_color="#00BFFF", border_color="#FFCC70", border_width=2, command=click_handler_check)
btn_check.place(relx=1.0, rely=0.5, anchor="center")

label_1 = CTkLabel(master=app, text="NAF", font=("Arial",20), text_color="#D2691E")
label_1.place(relx=0.5, rely=0.4, anchor="center")
label_4 = CTkLabel(master=app, text="NAF", font=("Arial",20), text_color="#D2691E")
label_4.place(relx=0.5, rely=0.5, anchor="center")
label_2 = CTkLabel(master=app, text="NAF", font=("Arial",20), text_color="#D2691E")
label_2.place(relx=0.5, rely=0.6, anchor="center")
label_3 = CTkLabel(master=app, text="NAF", font=("Arial",20), text_color="#D2691E")
label_3.place(relx=0.5, rely=0.7, anchor="center")


app.mainloop()