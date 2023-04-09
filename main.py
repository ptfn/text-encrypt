from Crypto.Cipher import AES, Salsa20, ChaCha20
from Crypto.Random import get_random_bytes
from PyQt5 import QtCore, QtGui, QtWidgets
from base64 import b64encode, b64decode
import sys


class Crypto():
    def convert_key(self, password, method=""):
        if method != "":
            length_algorithm = round(int(method[4:])/8)
        else:
            length_algorithm = 32

        length_key = len(password)

        if length_algorithm <= length_key:
            return password[:length_algorithm]
        elif length_algorithm > length_key:
            for i in range(length_algorithm-length_key):
                password += "0"
            return password.encode()

    def generate_cipher(self, password, algorithm, nonce):
        if algorithm[:3] == "AES":
            key = self.convert_key(password, algorithm)
            return AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce)
        elif algorithm == "Salsa20":
            key = self.convert_key(password)
            return Salsa20.new(key=key, nonce=nonce)
        elif algorithm == "ChaCha20":
            key = self.convert_key(password)
            return ChaCha20.new(key=key, nonce=nonce)

    def encrypt(self, cipher, text):
        ciphertext = cipher.encrypt(text.encode())
        return ciphertext

    def decrypt(self, cipher, ciphertext):
        text = cipher.decrypt(ciphertext)
        return text


class Window(object):
    def __init__(self):
        self.crypto = Crypto()

    def setupUi(self, MainWindow):
        # Window title and size
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(640, 480)

        # Central Widget
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        # TextBrowser
        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(10, 270, 620, 150))
        self.textBrowser.setObjectName("textBrowser")

        # TextEdit
        self.textEdit = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit.setGeometry(QtCore.QRect(10, 80, 620, 150))
        self.textEdit.setObjectName("textEdit")

        # ComboBox
        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(270, 15, 100, 25))
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("AES-128")
        self.comboBox.addItem("AES-192")
        self.comboBox.addItem("AES-256")
        self.comboBox.addItem("Salsa20")
        self.comboBox.addItem("ChaCha20")

        # PushButton
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(150, 435, 160, 40))
        self.pushButton.setObjectName("pushButton"),

        # PushButton2
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(320, 435, 160, 40))
        self.pushButton_2.setObjectName("pushButton_2")

        # Label
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(30, 60, 100, 15))
        self.label.setObjectName("label")

        # Label2
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(30, 250, 100, 15))
        self.label_2.setObjectName("label_2")

        # Label3
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(20, 20, 150, 15))
        self.label_3.setObjectName("label_3")

        MainWindow.setCentralWidget(self.centralwidget)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        # Connect Buttons
        self.pushButton.clicked.connect(lambda: self.encrypt_button())
        self.pushButton.setShortcut("Ctrl+E")
        self.pushButton_2.clicked.connect(lambda: self.decrypt_button())
        self.pushButton_2.setShortcut("Ctrl+D")

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.pushButton.setText(_translate("MainWindow", "Encrypt"))
        self.pushButton_2.setText(_translate("MainWindow", "Decrypt"))
        self.label.setText(_translate("MainWindow", "Source Text:"))
        self.label_2.setText(_translate("MainWindow", "Edited Text:"))
        self.label_3.setText(_translate("MainWindow", "Encryption Algorithm:"))

    def encrypt_button(self):
        try:
            text, ok = QtWidgets.QInputDialog.getText(None,
                                                      "Attention",
                                                      "Password",
                                                      QtWidgets.QLineEdit.Password)
            if ok and text:
                password = text

            # Collecting data from the widgets
            algorithm = self.comboBox.currentText()
            text = self.textEdit.toPlainText()
            nonce = get_random_bytes(8)

            # Clear data from the widget
            self.textBrowser.clear()
            self.textEdit.clear()

            if password != "" and text != "":
                # Generate cipher for encrypt
                cipher = self.crypto.generate_cipher(password,
                                                     algorithm,
                                                     nonce)

                # Encrypt
                ciphertext = self.crypto.encrypt(cipher, text)

                # Print ciphertext and nonce
                self.textBrowser.append(b64encode(ciphertext).decode())
                self.textBrowser.append(b64encode(nonce).decode())

        except UnboundLocalError:
            self.textBrowser.append("Did`n keep the password!")
        except Exception:
            self.textBrowser.append("Error encrypt!")

    def decrypt_button(self):
        try:
            text, ok = QtWidgets.QInputDialog.getText(None,
                                                      "Attention",
                                                      "Password?",
                                                      QtWidgets.QLineEdit.Password)

            if ok and text:
                password = text

            # Collecting data from the widgets
            algorithm = self.comboBox.currentText()
            text = self.textEdit.toPlainText()
            nonce = b64decode(text.split('\n')[1].encode())

            # Clear data from the widget
            self.textBrowser.clear()
            self.textEdit.clear()

            if password != "" and text != "":
                # Generate cipher for decrypt
                cipher = self.crypto.generate_cipher(password,
                                                     algorithm,
                                                     nonce)

                # Decrypt
                ciphertext = b64decode(text.split('\n')[0].encode())
                text = self.crypto.decrypt(cipher, ciphertext)

                # Print text
                self.textBrowser.append(text.decode())

        except UnboundLocalError:
            self.textBrowser.append("Did`n keep the password!")
        except Exception:
            self.textBrowser.append("Error decrypt!")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Window()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
