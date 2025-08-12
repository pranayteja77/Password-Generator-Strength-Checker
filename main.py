"""
SecurePass - Password Generator & Strength Checker
GitHub Achievement Project
"""

import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import re
import pyperclip  # For copy-to-clipboard functionality

class PasswordGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("SecurePass")
        self.root.geometry("400x400")
        self.root.resizable(False, False)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Arial', 10))
        self.style.configure('TButton', font=('Arial', 10))
        self.style.configure('Header.TLabel', font=('Arial', 14, 'bold'))
        
        self.create_widgets()






    
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        # Header
        header = ttk.Label(main_frame, text="SecurePass", style='Header.TLabel')
        header.pack(pady=(0, 20))
        
        # Password length
        length_frame = ttk.Frame(main_frame)
        length_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(length_frame, text="Password Length:").pack(side=tk.LEFT)
        self.length_var = tk.IntVar(value=12)
        self.length_spin = ttk.Spinbox(length_frame, from_=8, to=32, width=5, textvariable=self.length_var)
        self.length_spin.pack(side=tk.RIGHT)
        
        # Character types
        options_frame = ttk.Frame(main_frame)
        options_frame.pack(fill=tk.X, pady=10)
        
        self.lower_var = tk.BooleanVar(value=True)
        self.upper_var = tk.BooleanVar(value=True)
        self.digits_var = tk.BooleanVar(value=True)
        self.symbols_var = tk.BooleanVar(value=True)
        
        ttk.Checkbutton(options_frame, text="Lowercase (a-z)", variable=self.lower_var).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="Uppercase (A-Z)", variable=self.upper_var).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="Digits (0-9)", variable=self.digits_var).pack(anchor=tk.W)
        ttk.Checkbutton(options_frame, text="Symbols (!@#...)", variable=self.symbols_var).pack(anchor=tk.W)
        
        # Generate button
        ttk.Button(main_frame, text="Generate Password", command=self.generate_password).pack(pady=10)
        
        # Password display
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=self.password_var, font=('Arial', 12), state='readonly')
        password_entry.pack(fill=tk.X, pady=5)
        
        # Copy button
        ttk.Button(main_frame, text="Copy to Clipboard", command=self.copy_to_clipboard).pack(pady=5)
        
        # Strength meter
        ttk.Label(main_frame, text="Password Strength:").pack()
        self.strength_meter = ttk.Progressbar(main_frame, length=200, mode='determinate')
        self.strength_meter.pack(pady=5)
        self.strength_label = ttk.Label(main_frame, text="", style='TLabel')
        self.strength_label.pack()
        
        # Check password frame
        check_frame = ttk.Frame(main_frame)
        check_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(check_frame, text="Check existing password:").pack(anchor=tk.W)
        self.check_var = tk.StringVar()
        check_entry = ttk.Entry(check_frame, textvariable=self.check_var, show="*")
        check_entry.pack(fill=tk.X, pady=5)
        ttk.Button(check_frame, text="Check Strength", command=self.check_strength).pack(pady=5)
    
    def generate_password(self):
        """Generate password based on selected criteria"""
        length = self.length_var.get()
        char_sets = []
        
        if self.lower_var.get():
            char_sets.append(string.ascii_lowercase)
        if self.upper_var.get():
            char_sets.append(string.ascii_uppercase)
        if self.digits_var.get():
            char_sets.append(string.digits)
        if self.symbols_var.get():
            char_sets.append(string.punctuation)
        
        if not char_sets:
            messagebox.showerror("Error", "Please select at least one character type")
            return
        
        characters = ''.join(char_sets)
        password = ''.join(random.choice(characters) for _ in range(length))
        self.password_var.set(password)
        self.check_strength(password)
    
    def check_strength(self, password=None):
        """Check password strength and update meter"""
        if password is None:
            password = self.check_var.get()
            if not password:
                return
        
        score = 0
        length = len(password)
        
        # Length score
        score += min(length, 20)  # Max 20 points for length
        
        # Character diversity
        if re.search(r'[a-z]', password): score += 5
        if re.search(r'[A-Z]', password): score += 5
        if re.search(r'[0-9]', password): score += 5
        if re.search(r'[^a-zA-Z0-9]', password): score += 10
        
        # Deductions for patterns
        if re.search(r'(.)\1{2,}', password): score -= 10  # Repeated chars
        if password.lower() in ['password', '123456', 'qwerty']: score = 0
        
        # Calculate percentage (0-100)
        percentage = min(max(0, score), 100)
        self.strength_meter['value'] = percentage
        
        # Strength label
        if percentage < 40:
            strength = "Weak"
            color = "red"
        elif percentage < 70:
            strength = "Moderate"
            color = "orange"
        elif percentage < 90:
            strength = "Strong"
            color = "blue"
        else:
            strength = "Very Strong"
            color = "green"
        
        self.strength_label.config(text=f"{strength} ({percentage}%)", foreground=color)
    
    def copy_to_clipboard(self):
        """Copy password to clipboard"""
        password = self.password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showerror("Error", "No password to copy")

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()
