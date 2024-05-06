import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QTextEdit, QLineEdit, QLabel, QGroupBox, QStyleFactory, QStackedWidget, QMessageBox
from PyQt5.QtGui import QFont, QPixmap, QColor, QBrush, QPalette
from PyQt5.QtCore import Qt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class EncryptionApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Aplikasi Enkripsi")
        self.setGeometry(100, 100, 800, 600)
        self.setStyleSheet("background-color: #2c3e50;")

        self.key = None  # Kunci enkripsi akan diatur oleh user langsung

        # Layout dan komponen GUI
        central_widget = QWidget()
        main_layout = QVBoxLayout()

        self.stacked_widget = QStackedWidget()

        # Halaman Input
        input_page = QWidget()
        input_layout = QVBoxLayout()

        self.title_label = QLabel("Algoritma AES Test")
        self.title_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ecf0f1;
        """)
        self.title_label.setAlignment(Qt.AlignCenter)
        input_layout.addWidget(self.title_label)

        input_group = QGroupBox("Input")
        input_group.setStyleSheet("color: #ecf0f1;")
        input_box_layout = QVBoxLayout()
        self.text_input = QTextEdit()
        self.text_input.setPlaceholderText("Masukkan plaintext yang ingin dienkripsi")
        self.text_input.setStyleSheet("background-color: #34495e; color: #ecf0f1;")
        input_box_layout.addWidget(self.text_input)
        
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Masukkan kunci enkripsi (16 byte)")
        self.key_input.setStyleSheet("background-color: #34495e; color: #ecf0f1;")
        input_box_layout.addWidget(self.key_input)

        input_group.setLayout(input_box_layout)

        input_button_layout = QHBoxLayout()
        self.reset_button = QPushButton("Reset")
        self.reset_button.setStyleSheet("""
            QPushButton {
                background-color: #9b59b6;
                color: #ecf0f1;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #8e44ad;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.4);
            }
        """)
        self.reset_button.clicked.connect(self.reset_input)
        input_button_layout.addWidget(self.reset_button)
        
        self.encrypt_button = QPushButton("Enkripsi")
        self.encrypt_button.setStyleSheet("""
            QPushButton {
                background-color: #e67e22;
                color: #ecf0f1;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #d35400;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.4);
            }
        """)
        self.encrypt_button.clicked.connect(self.encrypt_text)
        input_button_layout.addWidget(self.encrypt_button)

        input_layout.addWidget(input_group)
        input_layout.addLayout(input_button_layout)
        input_page.setLayout(input_layout)

        # Halaman Output
        output_page = QWidget()
        output_layout = QVBoxLayout()
        
        self.output_title_label = QLabel("Algoritma AES Test")
        self.output_title_label.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ecf0f1;
        """)
        self.output_title_label.setAlignment(Qt.AlignCenter)
        output_layout.addWidget(self.output_title_label)
        
        output_group = QGroupBox("Output")
        output_group.setStyleSheet("color: #ecf0f1;")
        output_box_layout = QVBoxLayout()
        self.text_output = QTextEdit()
        self.text_output.setStyleSheet("background-color: #34495e; color: #ecf0f1;")
        output_box_layout.addWidget(self.text_output)
        output_group.setLayout(output_box_layout)

        output_button_layout = QHBoxLayout()
        self.back_button = QPushButton("Kembali")
        self.back_button.setStyleSheet("""
            QPushButton {
                background-color: #3498db;
                color: #ecf0f1;
                padding: 10px;
                border-radius: 5px;
            }
            QPushButton:hover {
                background-color: #2980b9;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.4);
            }
        """)
        self.back_button.clicked.connect(self.go_back_to_input_page)
        output_button_layout.addStretch()
        output_button_layout.addWidget(self.back_button)
        output_button_layout.addStretch()

        output_layout.addWidget(output_group)
        output_layout.addLayout(output_button_layout)
        output_page.setLayout(output_layout)

        self.stacked_widget.addWidget(input_page)
        self.stacked_widget.addWidget(output_page)

        main_layout.addWidget(self.stacked_widget)
        central_widget.setLayout(main_layout)
        self.setCentralWidget(central_widget)

    def encrypt(self, plaintext):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_plaintext = padder.update(plaintext.encode()) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        return iv + ciphertext

    def encrypt_text(self):
        plaintext = self.text_input.toPlainText()
        key_input = self.key_input.text()
        if len(key_input) != 16:
            QMessageBox.warning(self, "Kunci Enkripsi Tidak Valid", "Kunci enkripsi harus 16 byte (karakter).")
            return
        self.key = key_input.encode()
        ciphertext = self.encrypt(plaintext)
        self.text_output.setPlainText(ciphertext.hex())
        self.stacked_widget.setCurrentIndex(1)  # Pindah ke halaman output

    def go_back_to_input_page(self):
        self.stacked_widget.setCurrentIndex(0)  # Pindah ke halaman input

    def reset_input(self):
        self.text_input.clear()  # Hapus teks input
        self.key_input.clear()  # Hapus kunci enkripsi
        
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle(QStyleFactory.create('Fusion'))
    encryption_app = EncryptionApp()
    encryption_app.show()
    sys.exit(app.exec_())
