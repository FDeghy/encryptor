from Crypto.Hash import HMAC, MD5, SHA512
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import base64
import PySimpleGUI as sg

###### functions ######
def secret(passw: str):
    psw = passw.encode("UTF-8")
    iv = MD5.new(psw).hexdigest()
    sec = SHA512.new(psw).hexdigest()
    key = HMAC.new(sec.encode())
    key = key.update(psw).hexdigest()
    return key, iv

def encrypt(key, iv, data):
    text_pad = pad(data.encode("UTF-8"), AES.block_size)
    enc_aes = AES.new(bytearray(key, "UTF-8"), AES.MODE_CBC, bytearray.fromhex(iv))
    enc = enc_aes.encrypt(text_pad)
    enc = base64.b64encode(enc).decode("UTF-8")
    return enc

def decrypt(key, iv, data):
    try:
        enc_aes = AES.new(bytearray(key, "UTF-8"), AES.MODE_CBC, bytearray.fromhex(iv))
        dec = enc_aes.decrypt(base64.b64decode(data.encode("UTF-8")))
        dec = unpad(dec, AES.block_size).decode("UTF-8")
        return dec
    except Exception as ex:
        return "error: ", ex
###### /functions ######

###### gui ######
layout = [
    [sg.Text("Enter Pass")],
    [sg.In(key="passw", size=(50, 1))],
    [sg.Text("Enter Text")],
    [sg.Multiline(key="utext", size=(50, 20))],
    [sg.Button("Encrypt"), sg.Button("Decrypt")],
]

window = sg.Window(title="Encryptor :)", layout=layout)

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break
    if event == "Encrypt":
        enc = encrypt(*secret(values["passw"]), values["utext"])
        window["utext"].update(enc)
    elif event == "Decrypt":
        dec = decrypt(*secret(values["passw"]), values["utext"])
        if type(dec) != str:
            sg.popup_scrolled(f"ye ja ridi!\n{dec[0]+str(dec[1])}", title="fucking error :/", keep_on_top=True, size=(40, 10))
        else:
            window["utext"].update(dec)

window.close()
###### /gui ######