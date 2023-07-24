from tkinter import *
from tkinter import messagebox
import base64
def encode(key, clear):
    enc = []
    for i in range (len(clear)):
        key_c  = key [i% len (key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()
def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc). decode()
    for i in range (len (enc)):
        key_c = key [i % len (key)]
        dec_c = chr((256 + ord (enc[i]) - ord (key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrpy():
    tittle = entry.get()
    text = my_text.get("1.0",END)
    masterkey = password.get()

    if len(tittle) == 0 or len(text) == 0 or len(masterkey) == 0:
        messagebox.showwarning( message="Please enter all info.")
    else:
        message_encrypted = encode(masterkey, text)
        my_text.delete("1.0",END)
        entry.delete(0,END)
        password.delete(0,END)

        try:
            with open("My_secrets.txt","a") as data_file:
                data_file.write((f"\n{tittle}\n{message_encrypted}"))
        except FileNotFoundError:
            with open("my_secrets.txt","w") as data_file:
                data_file.write(f"\n{tittle}\n{message_encrypted},")

def dencrpy():
    message_encrypted = my_text.get("1.0", END)
    masterkey = password.get()

    if len(message_encrypted) == 0 or  len(masterkey) == 0:
        messagebox.showwarning( message="Please enter all info.")
    else:
        dencrypted_message = decode(masterkey,message_encrypted)
        my_text.delete("1.0", END)
        my_text.insert("1.0", dencrypted_message)
        try:
            dencrypted_message = decode(masterkey, message_encrypted)
            my_text.delete("1.0", END)
            my_text.insert("1.0", dencrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!")
window = Tk()

window.minsize(width=350, height=600)
window.title("My Secrets")


image1 = PhotoImage(file="secrets.png")
image_label= Label(window, image=image1, width=200,height=200)

#tittle1
first_tittle = Label(text="Enter Your Title")

#title_entey
entry = Entry(width=25)

#tittle2
text_tittle = Label(text="Enter Your Secrets")

#text_entry

my_entry = Entry(width= 20)
my_text =Text(width=40,height=15)

#title3
password_tittle=Label(text="Enter Master Key")

#password

password = Entry()
save_encrypt = Button(text="Save And Encrypt", command=save_and_encrpy)
decrypt = Button(text="Decrypt", command=dencrpy)

image_label.pack()
first_tittle.pack()
entry.pack()
text_tittle.pack()
my_text.pack()
password_tittle.pack()
password.pack()
save_encrypt.pack()
decrypt.pack()
window.mainloop()