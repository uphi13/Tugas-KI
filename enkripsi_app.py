import tkinter as tk
from tkinter import ttk, scrolledtext
from tkinter.font import Font

# Implementasi Algoritma RC4
def kunci_rc4(kunci):
    state = list(range(256))
    x = 0
    for i in range(256):
        x = (x + state[i] + ord(kunci[i % len(kunci)])) % 256
        state[i], state[x] = state[x], state[i]
    x = 0
    y = 0
    return state, x, y

def rc4(plainteks, state, x, y):
    cipher = []
    for char in plainteks:
        x = (x + 1) % 256
        y = (y + state[x]) % 256
        state[x], state[y] = state[y], state[x]
        cipher.append(chr(ord(char) ^ state[(state[x] + state[y]) % 256]))
    return ''.join(cipher)

# Fungsi Enkripsi
def enkripsi():
    plainteks = plaintext_entry.get("1.0", "end-1c")
    kunci = key_entry.get()
    state, x, y = kunci_rc4(kunci)
    ciphertext = rc4(plainteks, state, x, y)
    ciphertext_area.delete("1.0", "end")
    ciphertext_area.insert("1.0", ciphertext)

# Fungsi Dekripsi
def dekripsi():
    ciphertext = ciphertext_area.get("1.0", "end-1c")
    kunci = key_entry.get()
    state, x, y = kunci_rc4(kunci)
    plainteks = rc4(ciphertext, state, x, y)
    plaintext_entry.delete("1.0", "end")
    plaintext_entry.insert("1.0", plainteks)

# GUI
root = tk.Tk()
root.title("Enkripsi-Dekripsi RC4")
root.geometry("800x600")
root.configure(bg="#F7F9F9")  # Warna latar belakang cerah

# Membuat objek PhotoImage dari file gambar
encrypt_icon = tk.PhotoImage(file="encrypt_icon.png")
decrypt_icon = tk.PhotoImage(file="decrypt_icon.png")

# Input PlainText
plaintext_label = ttk.Label(root, text="Plaintext:", foreground="#2C3E50", background="#F7F9F9", font=("Roboto", 14))
plaintext_label.place(x=50, y=50)
plaintext_entry = scrolledtext.ScrolledText(root, width=40, height=5, foreground="#2C3E50", background="#ECF0F1", font=("Roboto Mono", 12))
plaintext_entry.place(x=200, y=50)

# Input Kunci
key_label = ttk.Label(root, text="Kunci:", foreground="#2C3E50", background="#F7F9F9", font=("Roboto", 14))
key_label.place(x=50, y=250)
key_entry = ttk.Entry(root, width=30, foreground="#2C3E50", background="#ECF0F1", font=("Roboto Mono", 12))
key_entry.place(x=200, y=250)

# Tombol Enkripsi
encrypt_button = ttk.Button(root, text="Enkripsi", command=enkripsi, style="Accent.TButton")
encrypt_button.place(x=50, y=300)

# Tombol Dekripsi
decrypt_button = ttk.Button(root, text="Dekripsi", command=dekripsi, style="Accent.TButton")
decrypt_button.place(x=200, y=300)

# Output Ciphertext
ciphertext_label = ttk.Label(root, text="Ciphertext:", foreground="#2C3E50", background="#F7F9F9", font=("Roboto", 14))
ciphertext_label.place(x=50, y=400)
ciphertext_area = scrolledtext.ScrolledText(root, width=40, height=5, foreground="#2C3E50", background="#ECF0F1", font=("Roboto Mono", 12))
ciphertext_area.place(x=200, y=400)

# Tambahkan style untuk tombol
style = ttk.Style(root)
style.theme_use("clam")
style.configure("Accent.TButton", foreground="#FFFFFF", background="#2E86C1", font=("Roboto", 12), padding=10, relief="raised")

# Tambahkan efek hover pada tombol
def on_enter(e):
    e.widget.configure(background="#2471A3")

def on_leave(e):
    e.widget.configure(background="#2E86C1")

encrypt_button.bind("<Enter>", on_enter)
encrypt_button.bind("<Leave>", on_leave)
decrypt_button.bind("<Enter>", on_enter)
decrypt_button.bind("<Leave>", on_leave)

# Tambahkan ikon pada tombol
encrypt_button.config(image=encrypt_icon, compound=tk.LEFT)
decrypt_button.config(image=decrypt_icon, compound=tk.LEFT)

# Mengatur font untuk tampilan yang lebih rapi
default_font = Font(family="Roboto", size=12)
root.option_add("*Font", default_font)

root.mainloop()