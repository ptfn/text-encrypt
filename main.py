from PyQt5 import QtCore, QtGui, QtWidgets
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import sys


class Crypto():
    def convert_key(self, password, method):
        length_algorithm = round(int(method[4:])/8)
        length_key = len(password)

        if length_algorithm <= length_key:
            return password[:length_algorithm]
        elif length_algorithm > length_key:
            for i in range(length_algorithm-length_key):
                password += "0"
            return password

    def encrypt(self, key, text):
        cipher = AES.new(key.encode(), AES.MODE_EAX)
        ciphertext = cipher.encrypt(text.encode())
        return ciphertext, cipher.nonce

    def decrypt(self, key, ciphertext, nonce):
        cipher = AES.new(key.encode(), AES.MODE_EAX, nonce)
        text = cipher.decrypt(ciphertext)
        return text


class Window(object):
    def __init__(self):
        self.aes = Crypto()

    def setupUi(self, MainWindow):
        # Window title and size
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(640, 480)

        # Central Widget
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")

        # TextBrowser
        self.textBrowser = QtWidgets.QTextBrowser(self.centralwidget)
        self.textBrowser.setGeometry(QtCore.QRect(330, 80, 300, 390))
        self.textBrowser.setObjectName("textBrowser")

        # TextEdit
        self.textEdit = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit.setGeometry(QtCore.QRect(10, 80, 310, 390))
        self.textEdit.setObjectName("textEdit")

        # LineEdit
        self.lineEdit = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit.setGeometry(QtCore.QRect(80, 15, 150, 25))
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit.setEchoMode(QtWidgets.QLineEdit.Password)

        # ComboBox
        self.comboBox = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox.setGeometry(QtCore.QRect(350, 15, 100, 25))
        self.comboBox.setObjectName("comboBox")
        self.comboBox.addItem("AES-128")
        self.comboBox.addItem("AES-192")
        self.comboBox.addItem("AES-256")

        # PushButton
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(460, 15, 80, 25))
        self.pushButton.setObjectName("pushButton"),

        # PushButton2
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(550, 15, 80, 25))
        self.pushButton_2.setObjectName("pushButton_2")

        # Label
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 20, 60, 15))
        self.label.setObjectName("label")

        # Label2
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(110, 60, 100, 15))
        self.label_2.setObjectName("label_2")

        # Label3
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(455, 60, 100, 15))
        self.label_3.setObjectName("label_3")

        # Label4
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(280, 20, 60, 15))
        self.label_4.setObjectName("label_4")

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
        self.label.setText(_translate("MainWindow", "Password"))
        self.label_2.setText(_translate("MainWindow", "Source Text"))
        self.label_3.setText(_translate("MainWindow", "Edited Text"))
        self.label_4.setText(_translate("MainWindow", "Algorithm"))

    def encrypt_button(self):
        try:
            # Collecting data from the widgets
            algorithm = self.comboBox.currentText()
            text = self.textEdit.toPlainText()
            password = self.lineEdit.text()

            # Converting password in key
            key = self.aes.convert_key(password, algorithm)

            # Encrypt
            ciphertext, nonce = self.aes.encrypt(key, text)

            # Clear data from the widget
            self.textBrowser.clear()
            self.textEdit.clear()
            self.lineEdit.clear()

            # Print ciphertext and nonce
            self.textBrowser.append(b64encode(ciphertext).decode())
            self.textBrowser.append(b64encode(nonce).decode())
        except Exception:
            print("* Error encrypt!")

    def decrypt_button(self):
        try:
            # Collecting data from the widgets
            algorithm = self.comboBox.currentText()
            text = self.textEdit.toPlainText()
            password = self.lineEdit.text()

            # Converting password in key
            key = self.aes.convert_key(password, algorithm)

            # Decrypt
            ciphertext = b64decode(text.split('\n')[0].encode())
            nonce = b64decode(text.split('\n')[1].encode())
            text = self.aes.decrypt(key, ciphertext, nonce)

            # Clear data from the widget
            self.textBrowser.clear()
            self.textEdit.clear()
            self.lineEdit.clear()

            # Print text
            self.textBrowser.append(text.decode())
        except Exception:
            print("* Error decrypt!")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Window()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
