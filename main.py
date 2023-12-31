import tkinter as tk
from PIL import Image, ImageTk
from io import BytesIO
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import tracemalloc
import time
from traitlets import HasDescriptors
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import threading 
from hashlib import pbkdf2_hmac
from traitlets import HasDescriptors
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from bitstring import BitArray
import base64
import binascii
from tkinter import messagebox

#anahtar türetme işlemlerini gerçekleştiren bir sınıf
class GenerateKey:
    def __init__(self, password, salt_length=16, key_size=128, iterations=100000):
        """
        password: Anahtarın türetilmesi için kullanılacak şifre.
        salt_length: Kullanılacak tuzun uzunluğu (varsayılan 16).
        key_size: Türetilen anahtarın boyutu (128 veya 192 bit, varsayılan 128).
        iterations: PBKDF2 algoritması için iterasyon sayısı (varsayılan 100,000).
        
        """
        self.password = password
        self.password_copy = password
        self.salt_length = salt_length
        self.key_size = key_size
        self.iterations = iterations

        #anahtar üretiminin kaç saniyede oldugunu hesaplamak için 
        self.key = None
        self.salt = None
        self.key_generation_time = 0 #süre değişkeni


    """Rastgele bir tuz oluşturur.
    Daha güvenli bir uygulama için tuz, kullanıcıya özgü olmalıdır. bu nedenle sistem saatını kullanarak entropi sağlanır.
    """
    def generate_salt(self):
        # Sistem saatini kullanarak rastgele bir tuz oluştur
        """
        generate_salt fonksiyonu sistem saatini kullanarak bir zaman damgası oluşturuyor ve bu değeri rastgele tuzun bir kısmı olarak kullanıyor. 
        """
        current_time = int(time.time())
        time_bytes = current_time.to_bytes(8, byteorder='big')
        random_bytes = get_random_bytes(self.salt_length - len(time_bytes))
        salt = time_bytes + random_bytes
        return salt
        
    
    """PBKDF2HMAC algoritmasını kullanarak anahtar türetilir."""
    def key_derivation(self, salt):
        kdf_key_size = self.key_size // 8
        try:
            #PBKDF2HMAC algoritması, HMAC'yi içeren bir türetime dayanır.
            """Key Stretching : Key stretching, saldırılara karşı direnci artırmak amacıyla, kullanıcı tarafından belirtilen başlangıç anahtarından türetilen anahtarın,
              belirli bir algoritma ve iterasyon sayısı kullanılarak daha uzun bir süreçte türetilmesidir. yani iterasyon kısmında bu uygulanmış oluyor.
            """
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                salt=salt,  # 'salt' parametresini burada kullanın
                iterations=self.iterations,
                length=kdf_key_size
            )
            # String'i bytes'e çevir
            #s_bytes = self.password.encode('utf-8')
            #key=binascii.b2a_base64(s_bytes,newline=False)
            key = kdf.derive(self.password.encode("utf-8"))
            return key
        except Exception as e:
            print(f"Key derivation error: {e}")
            return None
        
    """Tuz ve anahtarın birleşimi olarak anahtar üretilir. """
    def generate_key(self):
        start_time = time.time()
        salt = self.generate_salt()
        key = self.key_derivation(salt)
        end_time = time.time()
        if key is None:
            print("Anahtar üretme hatası.")
            return None, None  # Anahtar oluşturulamadıysa None değerlerini döndür
        self.key_generation_time = end_time - start_time
        #print(f"Anahtar üretildi süresi: {self.key_generation_time:.6f} saniye")
    
        return key, salt # ikili formatta bir byte dizisi olarak elde edildi anahtar
    

# Anahtar güncelleme işlemlerini gerçekleştiren sınıf
class KeyUpdater:
    def __init__(self, generate_key_instance, update_period=30):
        self.generate_key_instance = generate_key_instance
        self.update_period = update_period
        self.update_thread = threading.Thread(target=self.periodic_key_update)
        self.update_thread.daemon = True  # Ana program sona erdiğinde thread de sona ersin
        self.update_thread.start()

    #belirli aralıklarla anahtar güncelleme işlemi
    def periodic_key_update(self):
        while True:
            time.sleep(self.update_period)
            self.update_key()

    #GenerateKey sınıfındaki generate_key fonksiyonunu çağırarak yeni bir anahtar ve tuz üretir.
    def update_key(self):
        new_key, new_salt = self.generate_key_instance.generate_key()
        print("Anahtar Güncellendi")
        # Eski anahtarı ve tuzu güncelle
        self.generate_key_instance.key, self.generate_key_instance.salt = new_key, new_salt

        """
        anahtar güncelleme işlemi arka planda devam eder. Eski anahtar ve tuz kullanılmaz, 
        yerine güncellenmiş olanlar geçerli olur.
        """


#ŞİFRELEME ALGORİTMASI KISMI
class CustomEncryptor:
    def __init__(self):
        pass  

    def create_sbox(self):
        sbox = [
            [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
            [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xcc,0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
            [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
            [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
            [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
            [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
            [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0x5c,0x45, 0xf9, 0xf2, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
            [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
            [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
            [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
            [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
            [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
            [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0xde,0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
            [0xf8, 0x98, 0x11, 0x69, 0xd9, 0xbe, 0x94, 0x9b,0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
            [0x8c, 0x01, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
            [0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
        ]
        return sbox

    def encrypt(self,data,key,key_size):

        bits = ''.join(format(byte, '08b') for byte in data)
        #şifrelenecek metnin 128bite ve katlarına sabitlenmesi
        if len(bits) % 128 !=0:
            eklenecek_sifir=128-(len(bits)%128) 
            for j in range(eklenecek_sifir):               
                if j <= eklenecek_sifir/2:
                    bits="0"+bits
                else:
                    bits=bits+"0"
        #print(bits)
        #print(data)

        # Blocks oluştur
        blocks = self.create_block(bits)

        for block in blocks:
            R0, L0 = self.split_block(block)

            L0yeni=self.xor_blocks(R0,L0)

            R0=[]
            for i in range(len(L0)):
                bit = int(L0[i])
                R0.append(bit)

            L0=L0yeni

            changed_block=L0+R0
            state_matrix=self.create_state_matrix(changed_block)

            # for i in range(4):
            #     for j in range(4):
            #         print(state_matrix[i][j])

            #SBOX İŞLEMLERİ
            sbox = self.create_sbox() 
            substituted_block = self.substitute(state_matrix, sbox)

            # for i in range(4):
            #     for j in range(4):
            #         print(state_matrix[i][j])

            #ADD KEY
            key_bytes = bytes(key)
            plaintext = self.add_key(substituted_block, key_bytes)

            #print("Result Block:", plaintext)

        #self.label_result.config(text=f"Şifrelenmiş Veri: {ciphertext.hex()} - Tag: {tag.hex()} - IV: {iv.hex()}")
        return plaintext #şifrelenmiş metin döndürülür

    def create_block(self,bits):
        block_size = 128
        blocks = [bits[i:i+block_size] for i in range(0, len(bits), block_size)]

        return blocks

    def split_block(self,block):
        # Bloğu 64 bitlik parçalara böl
        half_length = len(block) // 2

        # R0 ve L0'ı ayır
        R0 = block[half_length:]
        L0 = block[:half_length]

        return R0, L0

    def xor_blocks(self, block1, block2):
        #result = [int(bit1) ^ int(bit2) for bit1, bit2 in zip(block1, block2)]
        result =[]     
        for i in range(len(block1)):
            bit1 = int(block1[i])
            bit2 = int(block2[i])
            result.append(bit1 ^ bit2)
        return result
    
    def create_state_matrix(self,input_block):
   
        bit_index = 0  # Verinin hangi bitinde olduğumuzu takip eden indeks
        state_matrix = [[0] * 4 for _ in range(4)]  # 4x4'lük bir matris oluştur

        for i in range(4):
            for j in range(4):
                eight_bits = input_block[bit_index:bit_index + 8]
                bits=''.join(format(byte, '01b') for byte in eight_bits)
                first_half = bits[:4]
                second_half = bits[4:]
                decimal_number_first = int(first_half, 2)  # İkili sayıyı ondalık sayıya çevir
                decimal_number_second = int(second_half, 2) 
                hex_number_first=hex(decimal_number_first)[2:]
                hex_number_second=hex(decimal_number_second)[2:]
                state_matrix[i][j] = hex_number_first+hex_number_second  
                bit_index += 8  
        return state_matrix
    

    #her bir bloğu (giriş değeri genelde 1byte) başka bloklarla değiştirme işlemi
    #giriş değeri matris kullanarak değiştirilir.
    #çıkış değeri üretilir.
    #input_block = "1101100010110101"
    def substitute(self, state_matrix, sbox):
        for i in range(4):
            for j in range(4):
                hex_string=state_matrix[i][j]
                # Hexadecimal stringi decimal (ondalık) bir sayıya çevir
                decimal_value = int(hex_string, 16)

                # S-Box matrisini kullanarak değeri değiştir
                substituted_value = sbox[int(hex_string[0], 16)][int(hex_string[1], 16)]
                # Decimal değeri tekrar hexadecimal stringe çevir ve geri döndür
                result_hex_string = format(substituted_value, '02x')  # 2 karakterlik bir hexadecimal stringe formatla
        
                state_matrix[i][j]=result_hex_string
        return state_matrix

    
   #parametreler ikili formatta string olmalı.1101101010101101 gibi
    def add_key(self,input_block, key_block):
        # Giriş bloğu ve şifreleme için kullanılan anahtar ikili sayıya çevir
        input_block_str = ''.join([''.join(row) for row in input_block]) #block yapıyor
        #print("input_block_str:",input_block_str)

        input_int = int(str(input_block_str), 16)
        # Anahtarı bytes'tan bir tam sayıya çevir
        key_int = int(key_block.hex(), 16)

        # XOR işlemi uygula
        result_block = input_int ^ key_int

        # Sonucu hexadecimal forma çevir
        result_block = format(result_block, '032x')  # 8 karakterlik bir hexadecimal stringe formatla

        return result_block
    

#DEŞİFRELEME ALGORİTMASI KISMI
class CustomDecryptor:
    def __init__(self):
        self.decrypts = CustomEncryptor()
        self.sbox =self.decrypts.create_sbox()
        

    def create_state_matrix(self,data):
        # Veriyi ikişerli bloklara ayır
        blocks = [data[i:i+2] for i in range(0, len(data), 2)]

        # 4x4'lük bir matris oluştur
        matrix = [blocks[i:i+4] for i in range(0, len(blocks), 4)]

        return matrix

    def inverse_add_key(self, input_block, key_block):
        # Giriş bloğunu ve şifreleme için kullanılan anahtarı ikili sayıya çevir
        input_int = int(input_block.hex(), 16)  # bytes'ı onaltılık stringe çeviriyoruz
        key_int = int(key_block.hex(), 16)

        # XOR işlemi uygula
        result_block = input_int ^ key_int

        # Sonucu hexadecimal forma çevir
        result_block = format(result_block, '032x')  # 8 karakterlik bir hexadecimal stringe formatla

        return result_block


    def substitute_inverse(self, state_matrix, sbox):
        for i in range(4):
            for j in range(4):
                element = state_matrix[i][j]
             
                # S-Box matrisini dolaşarak eşleşen konumu bul
                for x in range(16):
                    for y in range(16):
                        sbox_value_hex = format(sbox[x][y], '02x')
                        if element == sbox_value_hex:
                            combined_value = format((x << 4) + y, '02x')
                            state_matrix[i][j] = combined_value
      
        return state_matrix
    
    def matrix_to_block(self,matrix):
        block_matrix = ''.join([''.join(row) for row in matrix])
        return block_matrix
    
    def remove_padding(self, data):
        # Çözme işlemi sırasında eklenen sıfırları temizle
        if data.endswith(b'0'):
            data = data.rstrip(b'0')
        return data

    def decrypt(self, ciphertext, key, key_size,uzunluk):
        # Anahtarın byte türüne dönüştürülmesi
        #key_bytes = bytes(key)
        #key_bytes = bytes.fromhex(key)
        #key değişkeni byte türünde
        #bits = ''.join(format(byte, '08b') for byte in ciphertext)
        key_bytes = bytes(key)
        #key_bytes = bytes.fromhex(key)

        #key_bytes = key_bytes.decode('utf-8')
       
        plaintext = self.inverse_add_key(ciphertext, key_bytes)
        print("plaintext",plaintext)


        state_matrix = self.create_state_matrix(plaintext)

        # Matrisi yazdır
        for row in state_matrix:
            print("state_matrix :",row)
        
        #SBOXIN TERSTEN UYGULANMASI
        state_matris_yeni = self.substitute_inverse(state_matrix,self.sbox)

        for row in state_matris_yeni:
            print("state_matris_yeni:",row)

        #matris bloğa dönüştürülür
        block_matrix = self.matrix_to_block(state_matris_yeni)


        #bloğu ikiye ayır
        Y, X  = self.decrypts.split_block(block_matrix)

        input_Y = "{:064b}".format(int(Y, 16))
        input_X = "{:064b}".format(int(X, 16))

        #xor
        Z =self.decrypts.xor_blocks(input_X,input_Y)

        Z_str = [str(bit) for bit in Z]

        # string değerleri birleştirme
        Z_str = ''.join(Z_str)
   
        # #ters işlemler
        input_X=input_Y
        input_Y=Z_str

        sonuc =input_X+input_Y #byte

        eklenen_sifir_sayisi = 128-(uzunluk*8)

        for o in range(eklenen_sifir_sayisi):
            if o <= eklenen_sifir_sayisi // 2:
                sonuc = sonuc[1:]  # Baştan bir karakter sil
            else:
                sonuc = sonuc[:-1]  # Sondan bir karakter sil

        string_data=sonuc

        return string_data

    
"""ARAYÜZ VE ANA SINIF"""
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Şifreleme Uygulaması")
        self.root.geometry("800x600") #arayüz boyutu

        # Arkaplan rengini açık pembe olarak ayarla
        self.root.configure(bg='#FFB6C1')


        # Şifrelenecek Veri etiketi ve giriş kutusu
        self.label_data = tk.Label(root, text="Şifrelenecek Veri:", font=("Arial", 14),bg='#FFB6C1')
        self.label_data.pack(pady=10)
        self.entry_data = tk.Entry(root, font=("Arial", 12))
        self.entry_data.pack(pady=10)
        
        
    
        # Anahtar etiketi ve giriş kutusu
        self.label_key = tk.Label(root, text="Anahtar:", font=("Arial", 14),bg='#FFB6C1')
        self.label_key.pack(pady=10)
        self.entry_key = tk.Entry(root, font=("Arial", 12))
        self.entry_key.pack(pady=10)

        self.key_size_var = tk.IntVar()
        self.key_size_var.set(128)

        self.checkbox_key_size_128 = tk.Checkbutton(root, text="128 Bit", variable=self.key_size_var, onvalue=128, offvalue=0, font=("Arial", 12),bg='#FFB6C1')
        self.checkbox_key_size_128.pack()

        # GenerateKey sınıfını oluştur
        self.generate_key_instance = GenerateKey(password='')

        # KeyUpdater sınıfını oluştur ve GenerateKey sınıfını parametre olarak ver
        # arka planda çalışacak olan periodic_key_update fonksiyonunu içeren bir thread başlatılır.
        self.key_updater = KeyUpdater(self.generate_key_instance)


        # Şifreleme ve Çözme düğmeleri
        self.button_encrypt = tk.Button(root, text="Şifrele", command=self.encrypt_data, font=("Arial", 14),bg='#800080', fg='white')
        self.button_encrypt.pack(pady=10)
        self.button_decrypt = tk.Button(root, text="Çöz", command=self.decrypt_data, font=("Arial", 14),bg='#800080', fg='white')
        self.button_decrypt.pack(pady=10)

        # Şifrelenmiş/Çözülmüş Veri etiketi
        self.label_result = tk.Label(root, text="", font=("Arial", 12),bg='#FFB6C1')
        self.label_result.pack(pady=10)

        # Zaman ve Bellek Kullanımı etiketleri
        self.label_time = tk.Label(root, text="Zaman:", font=("Arial", 12))
        self.label_time.pack(pady=5)
        self.label_memory = tk.Label(root, text="Bellek Kullanımı:", font=("Arial", 12))
        self.label_memory.pack(pady=5)

        # Anahtar üretme süresini görüntülemek için etiket (label)
        self.label_key_generation_time = tk.Label(root, text="Anahtar Üretme Süresi: ",font=("Arial", 12))
        self.label_key_generation_time.pack(pady=5)

        # GenerateKey sınıfını oluşturacağız,şimdi bu değişken.
        self.generate_key_instance = None

        #şifreleme ve deşifreleme sınıfının nesneleri
        self.encryptor = CustomEncryptor()
        self.decryptor = CustomDecryptor()
        

    def generate_key(self):
        # Kullanıcının girdiği anahtarı al
        user_key = self.entry_key.get()
    
        # GenerateKey sınıfını oluştur (kullanıcıdan gelen anahtar ile)
        self.generate_key_instance = GenerateKey(password=user_key)
        #self.key = []  # Boş bir liste olarak başlat


        # Anahtar üretme işlemini başlat
        self.key, salt = self.generate_key_instance.generate_key()
        if self.key is None:
            print("Lütfen geçerli bir anahtar girin.")
            return
        print(f"Anahtar: {self.key.hex()}")
        print(f"Salt: {salt.hex()}")

        # Anahtar üretildiğinde kullanıcıya bildir
        print(f"Anahtar üretildi")
        
        # Anahtar üretme süresini görüntüle
        self.label_key_generation_time.config(text=f"Anahtar Üretme Süresi: {self.generate_key_instance.key_generation_time:.6f} saniye")
  
    #şifreleme kısmı
    def encrypt_data(self):
        if not self.generate_key_instance:
            self.generate_key()

        start_time = time.time()
        tracemalloc.start()

        data = self.entry_data.get().encode("utf-8")
        self.uzunluk = len(data)
        #data=base64.b64encode(self.entry_data.get()).decode("utf-8")
        key = self.entry_key.get().encode("utf-8")
        key_size = self.key_size_var.get()
        
        
        if len(key) != key_size // 8:
            self.label_result.config(text=f"Anahtar uzunluğu {key_size} bit için geçersiz.")
            messagebox.showwarning("Uyarı", "Anahtar uzunluğu geçersiz!")
            return
        #print(string_key)
        ciphertext = self.encryptor.encrypt(data,self.key,key_size) #şifrelenmiş veri
        #print(type(ciphertext))
       

        #self.encryptor.encrypt(data,key,key_size)
        self.label_result.config(text=f"Şifrelenmiş Veri: {ciphertext}\n ")

        end_time = time.time()
        elapsed_time = end_time - start_time
        self.label_time.config(text=f"Zaman: {elapsed_time:.6f} saniye")

        current, peak = tracemalloc.get_traced_memory()
        self.label_memory.config(text=f"Bellek Kullanımı: {current / 10*6:.6f} MB (Peak: {peak / 10*6:.6f} MB)")
        tracemalloc.stop()



    def decrypt_data(self):
        tracemalloc.start()

        # deşifreleme sonuçları
        result_text = self.label_result.cget("text")
        print("Result Text:", result_text)

        encrypted_data = result_text.split(": ")[1]
        encrypted_data = ''.join(encrypted_data.split())
        
        key = self.entry_key.get().encode("utf-8")
        key_size = self.key_size_var.get()

        if len(key) != key_size // 8:
            self.label_result.config(text=f"Anahtar uzunluğu {key_size} bit için geçersiz.")
            messagebox.showwarning("Uyarı", "Anahtar uzunluğu geçersiz!")
            return

        try:
            encrypted_data = bytes.fromhex(encrypted_data)
        except ValueError as ve:
            print("Hata Detayı:", ve)
            self.label_result.config(text="Hatalı hexadecimal format.")
            return
        
        # Deşifreleme işlemleri
        decrypted_data = self.decryptor.decrypt(encrypted_data, self.key, key_size,self.uzunluk)
        # 8'er 8'er bitlik parçalara ayır
        bit_parcalari = [decrypted_data[i:i+8] for i in range(0, len(decrypted_data), 8)]

        # Her 8 bitlik parçayı ASCII karaktere çevir
        kelime = ''.join([chr(int(parca, 2)) for parca in bit_parcalari])
        self.label_result.config(text=f"Çözülmüş Veri: {kelime}")


        current, peak = tracemalloc.get_traced_memory()
        self.label_memory.config(text=f"Bellek Kullanımı: {current / 10*6:.6f} MB (Peak: {peak / 10*6:.6f} MB)")
        tracemalloc.stop()


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()

#0123456789ABCDEF