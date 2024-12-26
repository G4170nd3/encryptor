import os
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sys
import time

SAVED_HASH_VAL = "5020cd8c259ac6563cd8525e9b6603ea69b4fc5fb2ccc4b690a41b39f8cda0da"
AES_IV = b"\x1c\x8b\xdbp-\x9f\xaaM\x87\x9f\xcf\x85\x13\xca\x1f\x05"
BLOCK_SIZE = 16

def file_op(file,pwd,encrypt): # encrypt is True or False
    
    with open(file,'rb') as f:
        data = f.read()
    
    if encrypt:
        aes_enc = AES.new(sha256(pwd).digest()[:16],AES.MODE_CBC,iv=AES_IV)
        enc_data = aes_enc.encrypt(pad(data,BLOCK_SIZE))
        with open(file,'wb') as f:
            f.write(enc_data)
        os.rename(file,file+".satyam")

    else:
        aes_dec = AES.new(sha256(pwd).digest()[:16],AES.MODE_CBC,iv=AES_IV)
        dec_data = unpad(aes_dec.decrypt(data),BLOCK_SIZE)
        with open(file,'wb') as f:
            f.write(dec_data)
        os.rename(file,file[:-7])

def close():
    print("Exiting in 3s ...")
    time.sleep(3)
    sys.exit(1)

def fetch_files():
    cur_path = os.getcwd()
    files = []
    for d,_,fa in os.walk(cur_path):
        if d == cur_path:
            continue
        for f in fa:
            files.append(os.path.join(d,f))
    return files

def enc_check(pwd,encrypt): # encrypt will contain true or false
    with open("enc.test",'rb') as f:
        text = f.read()

    if sha256(text).hexdigest() == SAVED_HASH_VAL:
        if not encrypt:
            return {"encrypt": False, "error": True, "error_msg": "Files are already decrypted!"}
        else:
            aes_enc = AES.new(sha256(pwd).digest()[:16],AES.MODE_CBC,iv=AES_IV)
            enc_text = aes_enc.encrypt(pad(text,BLOCK_SIZE))

            with open("enc.test","wb") as f:
                f.write(enc_text)

            return {"encrypt": True, "error": False}

    aes_dec = AES.new(sha256(pwd).digest()[:16],AES.MODE_CBC,iv=AES_IV)
    try:
        dec_text = unpad(aes_dec.decrypt(text),BLOCK_SIZE)
    except ValueError:
        print("Incorrect password!")
        close()

    if sha256(dec_text).hexdigest() == SAVED_HASH_VAL:
        if encrypt:
            return {"encrypt": True, "error": True, "error_msg": "Files are already encrypted!"}
        else:
            with open("enc.test",'wb') as f:
                f.write(dec_text)

            return {"encrypt": False, "error": False}

    return {"encrypt": None, "error": True, "error_msg": "Incorrect password!"}


def main():
    print(f"Welcome! do you wanna encrypt/decrypt [e/d]?")
    opt = input("> ").strip().lower()
    print(f"Password:")
    pwd = input("> ").strip().encode('utf-8')
    
    if opt == "e":
        file_check = enc_check(pwd,True)
        if file_check["error"]:
            print(file_check["error_msg"])
            close()

        assert file_check["encrypt"] == True

        print("Fetching files ...")
        files = fetch_files()
    
        print("Encrypting data ...")
        for file in files:
            if not file.endswith('.satyam'):
                file_op(file,pwd,True)
    
        print("DONE!")
        close()

    elif opt == "d":
        file_check = enc_check(pwd,False)
        if file_check["error"]:
            print(file_check["error_msg"])
            close()

        assert file_check["encrypt"] == False

        print("Fetching files ...")
        files = fetch_files()

        print("Decrypting data ...")
        for file in files:
            if file.endswith('.satyam'):
                file_op(file,pwd,False)
        
        print("DONE!")
        close()

    else:
        print("Dont waste my time!")
        close()

if __name__ == "__main__":
    main()
