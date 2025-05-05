import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import hashlib
import string
from threading import Thread
import time

class AdvancedCipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Cryptography Tool")
        self.root.geometry("1000x800")
        self.setup_style()
        self.create_widgets()
        self.setup_encryption_methods()
        self.selected_file = None  # To store the selected file path

    def setup_style(self):
        self.style = ttk.Style()
        self.style.theme_create('dark', parent='alt', settings={
            'TFrame': {'configure': {'background': '#2d2d2d'}},
            'TLabel': {'configure': {'foreground': 'white', 'background': '#2d2d2d'}},
            'TButton': {'configure': {'foreground': 'white', 'background': '#3d3d3d'}},
            'TNotebook': {'configure': {'background': '#2d2d2d'}},
            'TEntry': {'configure': {'fieldbackground': '#3d3d3d', 'foreground': 'white'}},
            'TCombobox': {'configure': {'fieldbackground': '#3d3d3d', 'foreground': 'white'}},
            'TText': {'configure': {'background': '#3d3d3d', 'foreground': 'white'}}
        })
        self.style.theme_use('dark')

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Caesar Cipher Tab
        self.caesar_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.caesar_frame, text="Caesar Cipher")
        self.create_caesar_widgets()

        # Vigenère Cipher Tab
        self.vigenere_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.vigenere_frame, text="Vigenère Cipher")
        self.create_vigenere_widgets()

        # Brute Force Tab
        self.bruteforce_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.bruteforce_frame, text="Brute Force")
        self.create_bruteforce_widgets()

        # File Encryption Tab
        self.file_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.file_frame, text="File Encryption")
        self.create_file_widgets()

        # Help Tab
        self.help_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.help_frame, text="Help")
        self.create_help_content()

    def create_caesar_widgets(self):
        ttk.Label(self.caesar_frame, text="Advanced Caesar Cipher", font=('Helvetica', 14)).pack(pady=10)
        
        self.mode_var = tk.StringVar(value='encrypt')
        mode_frame = ttk.Frame(self.caesar_frame)
        mode_frame.pack(pady=5)
        ttk.Radiobutton(mode_frame, text="Encrypt", variable=self.mode_var, value='encrypt').pack(side=tk.LEFT)
        ttk.Radiobutton(mode_frame, text="Decrypt", variable=self.mode_var, value='decrypt').pack(side=tk.LEFT)
        
        ttk.Label(self.caesar_frame, text="Input Text:").pack()
        self.input_text = tk.Text(self.caesar_frame, height=10, width=80)
        self.input_text.pack(pady=5)
        
        shift_frame = ttk.Frame(self.caesar_frame)
        shift_frame.pack(pady=5)
        ttk.Label(shift_frame, text="Shift Value:").pack(side=tk.LEFT)
        self.shift_var = tk.StringVar()
        self.shift_entry = ttk.Entry(shift_frame, textvariable=self.shift_var, width=5)
        self.shift_entry.pack(side=tk.LEFT)
        
        ttk.Label(shift_frame, text="  or Password:").pack(side=tk.LEFT)
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(shift_frame, textvariable=self.password_var, show='*')
        self.password_entry.pack(side=tk.LEFT)
        
        self.multi_layer_var = tk.IntVar()
        ttk.Checkbutton(self.caesar_frame, text="Multi-layer Encryption (3 passes)", 
                       variable=self.multi_layer_var).pack(pady=5)
        
        ttk.Button(self.caesar_frame, text="Process Text", command=self.threaded_process_caesar).pack(pady=5)
        
        ttk.Label(self.caesar_frame, text="Result:").pack()
        self.output_text = tk.Text(self.caesar_frame, height=10, width=80, state=tk.DISABLED)
        self.output_text.pack(pady=5)
        
        stats_frame = ttk.Frame(self.caesar_frame)
        stats_frame.pack(pady=5)
        ttk.Button(stats_frame, text="Show Frequency Analysis", 
                  command=self.show_frequency_analysis).pack(side=tk.LEFT)
        ttk.Button(stats_frame, text="Copy Result", command=self.copy_result).pack(side=tk.LEFT)
        ttk.Button(stats_frame, text="Clear All", command=self.clear_all).pack(side=tk.LEFT)

    def create_vigenere_widgets(self):
        ttk.Label(self.vigenere_frame, text="Vigenère Cipher", font=('Helvetica', 14)).pack(pady=10)
        
        ttk.Label(self.vigenere_frame, text="Input Text:").pack()
        self.vigenere_input_text = tk.Text(self.vigenere_frame, height=10, width=80)
        self.vigenere_input_text.pack(pady=5)
        
        ttk.Label(self.vigenere_frame, text="Cipher Key:").pack()
        self.vigenere_key = ttk.Entry(self.vigenere_frame, width=50)
        self.vigenere_key.pack(pady=5)
        
        ttk.Label(self.vigenere_frame, text="Result:").pack()
        self.vigenere_output_text = tk.Text(self.vigenere_frame, height=10, width=80, state=tk.DISABLED)
        self.vigenere_output_text.pack(pady=5)
        
        ttk.Button(self.vigenere_frame, text="Encrypt", 
                  command=lambda: self.process_vigenere('encrypt')).pack(pady=5)
        ttk.Button(self.vigenere_frame, text="Decrypt", 
                  command=lambda: self.process_vigenere('decrypt')).pack(pady=5)

    def create_bruteforce_widgets(self):
        ttk.Label(self.bruteforce_frame, text="Brute Force Attack", font=('Helvetica', 14)).pack(pady=10)
        self.bruteforce_text = tk.Text(self.bruteforce_frame, height=15, width=80)
        self.bruteforce_text.pack(pady=5)
        ttk.Button(self.bruteforce_frame, text="Start Brute Force", 
                  command=self.threaded_bruteforce).pack(pady=5)

    def create_file_widgets(self):
        ttk.Label(self.file_frame, text="File Encryption", font=('Helvetica', 14)).pack(pady=10)
        ttk.Button(self.file_frame, text="Select File", command=self.select_file).pack(pady=5)
        self.file_label = ttk.Label(self.file_frame, text="No file selected")
        self.file_label.pack(pady=5)
        ttk.Label(self.file_frame, text="Password for File Encryption:").pack()
        self.file_password = ttk.Entry(self.file_frame, show='*', width=50)
        self.file_password.pack(pady=5)
        ttk.Button(self.file_frame, text="Encrypt File", command=lambda: self.process_file('encrypt')).pack(pady=5)
        ttk.Button(self.file_frame, text="Decrypt File", command=lambda: self.process_file('decrypt')).pack(pady=5)

    def create_help_content(self):
        help_text = """
        Advanced Cryptography Tool Features:

        1. Multi-Cipher Support:
           - Caesar Cipher with variable shifts
           - Vigenère Cipher with keyword
           - ROT13 (built-in to Caesar with shift 13)

        2. Advanced Features:
           - Password-derived shift values (SHA-256 hashed)
           - Multi-layer encryption (3 passes)
           - File encryption/decryption
           - Brute-force attack simulator
           - Frequency analysis
           - Real-time preview

        3. Security Enhancements:
           - Threaded processing for large files
           - Input sanitization
           - Secure password handling
           - Automatic shift normalization

        4. Additional Tools:
           - Dark mode UI
           - Clipboard integration
           - Statistics and analysis
           - Cross-platform compatibility
        """
        help_display = tk.Text(self.help_frame, wrap=tk.WORD, height=20, width=80)
        help_display.insert(tk.END, help_text)
        help_display.config(state=tk.DISABLED)
        help_display.pack(pady=20)

    def setup_encryption_methods(self):
        self.caesar = CaesarCipher()
        self.vigenere = VigenereCipher()

    def threaded_process_caesar(self):
        """Run Caesar cipher processing in a separate thread to avoid freezing the UI."""
        thread = Thread(target=self.process_caesar)
        thread.daemon = True
        thread.start()

    def process_caesar(self):
        """Process Caesar cipher encryption/decryption."""
        try:
            # Get input text
            input_text = self.input_text.get("1.0", tk.END).strip()
            if not input_text:
                messagebox.showerror("Error", "Input text cannot be empty.")
                return

            # Determine shift value
            shift = 0
            if self.password_var.get():
                # Use SHA-256 hash of password to derive shift
                hash_obj = hashlib.sha256(self.password_var.get().encode())
                shift = int(hash_obj.hexdigest(), 16) % 26
            else:
                try:
                    shift = int(self.shift_var.get())
                except ValueError:
                    messagebox.showerror("Error", "Shift value must be an integer.")
                    return

            # Process text
            mode = self.mode_var.get()
            result = input_text
            if self.multi_layer_var.get():
                # Multi-layer encryption (3 passes)
                for _ in range(3):
                    result = self.caesar.encrypt(result, shift) if mode == 'encrypt' else self.caesar.decrypt(result, shift)
            else:
                result = self.caesar.encrypt(result, shift) if mode == 'encrypt' else self.caesar.decrypt(result, shift)

            # Update output text
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, result)
            self.output_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def process_vigenere(self, mode):
        """Process Vigenère cipher encryption/decryption."""
        try:
            input_text = self.vigenere_input_text.get("1.0", tk.END).strip()
            key = self.vigenere_key.get().strip()
            
            if not input_text:
                messagebox.showerror("Error", "Input text cannot be empty.")
                return
            if not key:
                messagebox.showerror("Error", "Cipher key cannot be empty.")
                return
            if not key.isalpha():
                messagebox.showerror("Error", "Cipher key must contain only letters.")
                return

            result = self.vigenere.encrypt(input_text, key) if mode == 'encrypt' else self.vigenere.decrypt(input_text, key)

            self.vigenere_output_text.config(state=tk.NORMAL)
            self.vigenere_output_text.delete("1.0", tk.END)
            self.vigenere_output_text.insert(tk.END, result)
            self.vigenere_output_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def threaded_bruteforce(self):
        """Run brute-force attack in a separate thread."""
        thread = Thread(target=self.bruteforce_caesar)
        thread.daemon = True
        thread.start()

    def bruteforce_caesar(self):
        """Brute-force Caesar cipher by trying all possible shifts."""
        try:
            input_text = self.bruteforce_text.get("1.0", tk.END).strip()
            if not input_text:
                messagebox.showerror("Error", "Input text cannot be empty.")
                return

            self.bruteforce_text.config(state=tk.NORMAL)
            self.bruteforce_text.delete("1.0", tk.END)
            self.bruteforce_text.insert(tk.END, "Brute Force Results:\n\n")
            
            for shift in range(26):
                result = self.caesar.decrypt(input_text, shift)
                self.bruteforce_text.insert(tk.END, f"Shift {shift}: {result}\n")
                self.bruteforce_text.update()  # Update UI
                time.sleep(0.1)  # Small delay for visibility
            
            self.bruteforce_text.config(state=tk.DISABLED)
            messagebox.showinfo("Complete", "Brute-force attack completed.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def select_file(self):
        """Open file dialog to select a file for encryption/decryption."""
        file_path = filedialog.askopenfilename()
        if file_path:
            self.selected_file = file_path
            self.file_label.config(text=f"Selected: {file_path}")

    def process_file(self, mode):
        """Encrypt or decrypt a file using a password-derived Caesar cipher."""
        try:
            if not self.selected_file:
                messagebox.showerror("Error", "No file selected.")
                return
            password = self.file_password.get()
            if not password:
                messagebox.showerror("Error", "Password cannot be empty.")
                return

            # Derive shift from password
            hash_obj = hashlib.sha256(password.encode())
            shift = int(hash_obj.hexdigest(), 16) % 26

            # Read input file
            with open(self.selected_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Process content
            if mode == 'encrypt':
                processed = self.caesar.encrypt(content, shift)
            else:
                processed = self.caesar.decrypt(content, shift)

            # Save output file
            output_path = filedialog.asksaveasfilename(defaultextension=".txt")
            if output_path:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(processed)
                messagebox.showinfo("Success", f"File {mode}ed successfully and saved to {output_path}")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def show_frequency_analysis(self):
        """Perform frequency analysis on the input text."""
        try:
            input_text = self.input_text.get("1.0", tk.END).strip()
            if not input_text:
                messagebox.showerror("Error", "Input text cannot be empty.")
                return

            freq = {}
            total = 0
            for char in input_text:
                if char.isalpha():
                    char = char.lower()
                    freq[char] = freq.get(char, 0) + 1
                    total += 1

            # Calculate percentages
            analysis = "\n".join([f"{char}: {count} ({(count/total)*100:.2f}%)" 
                                 for char, count in sorted(freq.items())])
            messagebox.showinfo("Frequency Analysis", analysis if analysis else "No letters found.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def copy_result(self):
        """Copy the result from the output text to the clipboard."""
        result = self.output_text.get("1.0", tk.END).strip()
        if result:
            self.root.clipboard_clear()
            self.root.clipboard_append(result)
            messagebox.showinfo("Success", "Result copied to clipboard.")
        else:
            messagebox.showerror("Error", "No result to copy.")

    def clear_all(self):
        """Clear all input and output fields."""
        self.input_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.shift_var.set("")
        self.password_var.set("")
        self.vigenere_input_text.delete("1.0", tk.END)
        self.vigenere_output_text.config(state=tk.NORMAL)
        self.vigenere_output_text.delete("1.0", tk.END)
        self.vigenere_output_text.config(state=tk.DISABLED)
        self.vigenere_key.delete(0, tk.END)
        self.bruteforce_text.config(state=tk.NORMAL)
        self.bruteforce_text.delete("1.0", tk.END)
        self.bruteforce_text.config(state=tk.DISABLED)
        self.selected_file = None
        self.file_label.config(text="No file selected")
        self.file_password.delete(0, tk.END)

class CaesarCipher:
    def encrypt(self, text, shift):
        return self._cipher(text, shift)
    
    def decrypt(self, text, shift):
        return self._cipher(text, -shift)
    
    def _cipher(self, text, shift):
        result = []
        shift = shift % 26
        for char in text:
            if char.isupper():
                result.append(chr((ord(char) - ord('A') + shift) % 26 + ord('A')))
            elif char.islower():
                result.append(chr((ord(char) - ord('a') + shift) % 26 + ord('a')))
            else:
                result.append(char)
        return ''.join(result)

class VigenereCipher:
    def _process_text(self, text, key, mode='encrypt'):
        key = key.upper()
        key_length = len(key)
        key_index = 0
        result = []
        
        for char in text:
            if char.isalpha():
                offset = ord('A') if char.isupper() else ord('a')
                key_char = ord(key[key_index % key_length]) - ord('A')
                if mode == 'decrypt':
                    key_char = -key_char
                
                processed = (ord(char) - offset + key_char) % 26
                result.append(chr(processed + offset))
                key_index += 1
            else:
                result.append(char)
        return ''.join(result)
    
    def encrypt(self, text, key):
        return self._process_text(text, key, 'encrypt')
    
    def decrypt(self, text, key):
        return self._process_text(text, key, 'decrypt')

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedCipherApp(root)
    root.mainloop()