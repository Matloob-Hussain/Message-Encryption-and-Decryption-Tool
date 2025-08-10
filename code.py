#Gui Tkinter project
import tkinter as tk
from tkinter import messagebox, filedialog
from PIL import Image, ImageTk
import base64
import hashlib
from cryptography.fernet import Fernet
import os

# Generate key from password
def generate_key(password):
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Encrypt
def encrypt_message():
    password = password_entry.get()
    message = text_entry.get("1.0" , tk.END).strip()
    if not password or not message:
        messagebox.showerror("Error", "Password and message required!")
        return
    try:
        key = generate_key(password)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(message.encode()).decode()
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, encrypted)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Decrypt
def decrypt_message():
    password = password_entry.get()
    encrypted_msg = text_entry.get("1.0", tk.END).strip()
    if not password or not encrypted_msg:
        messagebox.showerror("Error", "Password and message required!")
        return
    try:
        key = generate_key(password)
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted_msg.encode()).decode()
        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, decrypted)
    except:
        messagebox.showerror("Error", "Wrong password or message!")

# Toggle dark/light theme
def toggle_theme():
    global dark_mode
    dark_mode = not dark_mode
    apply_theme()

# Apply theme colors
def apply_theme():
    bg = "#222" if dark_mode else "#f0f0f0"
    fg = "#fff" if dark_mode else "#000"
    entry_bg = "#333" if dark_mode else "#fff"

    root.config(bg=bg)
    canvas.config(bg=bg)
    for w in all_widgets:
        w.config(bg=bg, fg=fg)
    password_entry.config(bg=entry_bg, fg=fg, insertbackground=fg)
    text_entry.config(bg=entry_bg, fg=fg, insertbackground=fg)
    result_text.config(bg=entry_bg, fg=fg, insertbackground=fg)

    encrypt_btn.config(bg="#28a745", fg="white")
    decrypt_btn.config(bg="#007bff", fg="white")
    theme_btn.config(bg="#555555" if dark_mode else "#dddddd", fg=fg)
    save_btn.config(bg="#ffc107", fg="black")
    load_btn.config(bg="#17a2b8", fg="white")
    copy_btn.config(bg="#6c757d", fg="white")
    toggle_pass_btn.config(bg="#444" if dark_mode else "#ccc", fg=fg)

# Save output
def save_to_file():
    content = result_text.get("1.0", tk.END).strip()
    if not content:
        messagebox.showwarning("Empty", "No output to save.")
        return
    file = filedialog.asksaveasfilename(defaultextension=".txt",
                                         filetypes=[("Text Files", "*.txt")])
    if file:
        with open(file, "w", encoding="utf-8") as f:
            f.write(content)
        messagebox.showinfo("Saved", f"Saved to:\n{file}")

# Load text
def load_from_file():
    file = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if file:
        with open(file, "r", encoding="utf-8") as f:
            data = f.read()
        text_entry.delete("1.0", tk.END)
        text_entry.insert(tk.END, data)

# Copy output
def copy_to_clipboard():
    output = result_text.get("1.0", tk.END).strip()
    if output:
        root.clipboard_clear()
        root.clipboard_append(output)
        root.update()
        messagebox.showinfo("Copied", "Output copied!")

# Show/Hide password
def toggle_password():
    if password_entry.cget("show") == "*":
        password_entry.config(show="")
        toggle_pass_btn.config(text="See it")
    else:
        password_entry.config(show="*")
        toggle_pass_btn.config(text="Seen")

# ========== GUI SETUP ==========
root = tk.Tk()
root.title(" Secret Message Tool")
root.geometry("500x650")
root.resizable(False, False)

# Optional icon
if os.path.exists("lock.ico"):
    root.iconbitmap("lock.ico")

# Background Image
canvas = tk.Canvas(root, width=500, height=650)
canvas.pack(fill="both", expand=True)

if os.path.exists("bg.jpg"):
    bg_img = Image.open("bg.jpg").resize((500, 650))
    bg = ImageTk.PhotoImage(bg_img)
    canvas.create_image(0, 0, anchor="nw", image=bg)

dark_mode = False

# Widgets
title = tk.Label(root, text=" Secret Message Tool", font=("Arial", 16, "bold"))
pass_label = tk.Label(root, text="Enter Password:", font=("Arial", 12))
password_entry = tk.Entry(root, font=("Arial", 12), show="*")
toggle_pass_btn = tk.Button(root, text="O", font=("Arial", 10), command=toggle_password)

text_label = tk.Label(root, text="Enter Message / Encrypted Text:", font=("Arial", 12))
text_entry = tk.Text(root, height=5, font=("Arial", 12))

encrypt_btn = tk.Button(root, text="Encrypt", command=encrypt_message, font=("Arial", 12))
decrypt_btn = tk.Button(root, text="Decrypt", command=decrypt_message, font=("Arial", 12))
load_btn = tk.Button(root, text="Load from File", command=load_from_file, font=("Arial", 12))
save_btn = tk.Button(root, text="Save Output", command=save_to_file, font=("Arial", 12))
copy_btn = tk.Button(root, text="Copy to Clipboard", command=copy_to_clipboard, font=("Arial", 12))
theme_btn = tk.Button(root, text="Click to change the Theme", command=toggle_theme, font=("Arial", 12))

result_label = tk.Label(root, text="Output:", font=("Arial", 12))
result_text = tk.Text(root, height=5, font=("Arial", 12))

# Place widgets on canvas
canvas.create_window(250, 40, window=title)
canvas.create_window(250, 80, window=pass_label)
canvas.create_window(220, 110, window=password_entry, width=250)
canvas.create_window(390, 110, window=toggle_pass_btn, width=40)

canvas.create_window(250, 160, window=text_label)
canvas.create_window(250, 200, window=text_entry, width=400, height=100)

canvas.create_window(250, 260, window=encrypt_btn, width=180)
canvas.create_window(250, 300, window=decrypt_btn, width=180)
canvas.create_window(250, 340, window=load_btn, width=180)
canvas.create_window(250, 380, window=save_btn, width=180)
canvas.create_window(250, 420, window=copy_btn, width=180)
canvas.create_window(250, 460, window=theme_btn, width=190)

canvas.create_window(250, 510, window=result_label)
canvas.create_window(250, 560, window=result_text, width=400, height=150)

# Theme support
all_widgets = [title, pass_label, text_label, result_label]

apply_theme()
root.mainloop()