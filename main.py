import random
import sys
import tkinter as tk
from tkinter import *
from tkinter import filedialog as fd

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Signature import pkcs1_15

import trng

# old_stdout = sys.stdout
#
# log_file = open('log.log', 'w')
# sys.stdout = log_file

file = dict(file_path="", content="")


def import_file():
    filetypes = (
        ('Pliki tekstowe', '*.txt'),
        ('Wszystkie pliki', '*.*'))

    filepath = fd.askopenfilename(
        title='Open a file',
        initialdir='/',
        filetypes=filetypes)

    try:
        with open(filepath, 'r') as text_file:
            input_file = text_file.readlines()
            text_file.close()
        print("[Successfully imported selected file]")
    except Exception as e:
        print("[Error importing selected file]", e)

    # input_file = open(filepath, 'r').readlines()

    file['file_path'] = filepath
    for idx in input_file:
        file['content'] += idx

    disp_name = filepath.split('/')[len(filepath.split('/')) - 1]

    # if file selected then block input block
    if filepath != "":
        print('[File selected]', disp_name)
        label3['text'] = disp_name
        disable_entry()


def generate_keys():
    # generate key pair
    key_pair = RSA.generate(bits=1024, randfunc=trng.rando)

    test = Random.get_random_bytes(3)
    print(test)
    test2 = trng.rando(3)
    print(test2)

    # print(key_pair)
    # print(key_pair.publickey())
    #
    # print(key_pair.exportKey())
    # print(key_pair.publickey().exportKey())

    private_key = key_pair.exportKey('PEM')  # private key for hashing
    public_key = key_pair.publickey().exportKey('PEM')  # public key for exchange

    try:
        with open('master_private.pem', 'wb') as keyfile:
            keyfile.write(private_key)
            keyfile.close()
        print("[Successfully created your RSA PRIVATE key]")
    except Exception as e:
        print("[Error creating your key]", e)

    try:
        with open("master_public.pem", "wb") as keyfile:
            keyfile.write(public_key)
            keyfile.close()
        print("[Successfully created your RSA PUBLIC key]")
    except Exception as e:
        print("[Error creating your key]", e)


def sign_file():
    # opening required data
    if file['content'] != "":
        # msg_raw = file['content']
        msg = bytes(file['content'], 'utf-8')
    else:
        # msg_raw = get_message()
        msg = bytes(get_message(), 'utf-8')

    # print(msg_raw)
    print('[Message to sign:] ' + msg.decode())

    try:
        private_key: RsaKey = RSA.import_key(open('master_private.pem').read())
    except Exception as e:
        print("[Error opening private key]", e)

    # signing procedure
    hasher = SHA256.new(msg)
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(hasher)
    # signature = pkcs1_15.new(private_key).sign(hasher)
    # print("Signature:", signature)

    try:
        with open("signed_file", "wb") as signed_file:
            signed_file.write(signature)
            signed_file.close()
        print("[Successfully signed your message!]")
    except Exception as e:
        print("[Error signing your message]", e)


def check_signature():
    # RSA verify signature
    if file['content'] != "":
        msg = bytes(file['content'], 'utf-8')
    else:
        msg = bytes(get_message(), 'utf-8')

    print('[Message to verify:] ' + msg.decode())

    try:
        public_key = RSA.import_key(open('master_public.pem').read())
    except Exception as e:
        print("[Error opening public key]", e)

    hasher = SHA256.new(msg)

    try:
        with open('signed_file', 'rb') as signed_file:
            signature = signed_file.read()
    except Exception as e:
        print("[Error opening your message]", e)

    try:
        pkcs1_15.new(public_key).verify(hasher, signature)
        print('[Signature is valid!]')
    except Exception as e:
        print('[Signature is NOT valid] The message was signed with other private key or modified')

    # try:
    #     rsa.verify(msg, signature, key)
    #     print('[Signature is valid!]')
    # except Exception as e:
    #     print('[Signature is NOT valid] The message was signed with the wrong private key or modified')


# ---------- windows element editing ----------
def disable_entry():
    user_input.config(state="disabled")


def get_message():
    # print(user_input.get())
    return user_input.get()


def open_popup():
    top = Toplevel(root)
    root.eval(f'tk::PlaceWindow {str(top)} center')
    top.geometry("250x150")
    top.resizable(False, False)
    top.configure(background='#FFFFFF')
    top.title("TRN")
    number = trng.rando(16)
    Label(top, text=number, bg='#FFFFFF', font=('Arial 18 bold')).pack(side=TOP, expand=YES)


# ---------------- main window ----------------
root = Tk()

root.eval('tk::PlaceWindow . center')
root.geometry('500x250')
root.resizable(False, False)
root.configure(background='#FFFFFF')
root.title('Digital Signature Wizard')
root.iconbitmap('icon.ico')

# labels
label1 = Label(root, text='Import file to sign or verify', bg='#FFFFFF')
label1.place(x=40, y=30)
label2 = Label(root, text='Input your message to sign or verify', bg='#FFFFFF')
label2.place(x=40, y=70)

# input box
user_input = Entry(root, bg='#F9F9F9')
user_input.place(x=250, y=70)

# import file block
button3 = tk.Button(text='Choose file', command=import_file)
button3.place(x=250, y=30)
label3 = Label(text='No file chosen', bg='#FFFFFF')
label3.place(x=325, y=30)

# action buttons block
Button(root, text='Generate keys', width=12, command=generate_keys).place(x=95, y=170)
Button(root, text='Sign file', width=12, command=sign_file).place(x=205, y=170)
Button(root, text='Check signature', width=12, command=check_signature).place(x=315, y=170)

# Button(root, text='Check random', width=12, command=lambda: print(trng.rando(8))).place(x=210, y=200)

root.mainloop()


# sys.stdout = old_stdout
# log_file.close()
