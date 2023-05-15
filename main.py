from Crypto.Cipher import AES, Salsa20, ChaCha20
from Crypto.Random import get_random_bytes
from PyQt5 import QtCore, QtGui, QtWidgets
from base64 import b64encode, b64decode
import time
import sys
import os


class Crypto():
    # Converting the key to the right size (length)
    def convertKey(self, password, method=""):
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

    # Generate cipher for encrypt and decrypt data
    def generateCipher(self, password, algorithm, nonce):
        if algorithm[:3] == "AES":
            key = self.convertKey(password, algorithm)
            return AES.new(key=key, mode=AES.MODE_EAX, nonce=nonce)
        elif algorithm == "Salsa20":
            key = self.convertKey(password)
            return Salsa20.new(key=key, nonce=nonce)
        elif algorithm == "ChaCha20":
            key = self.convertKey(password)
            return ChaCha20.new(key=key, nonce=nonce)

    # Encrypt text and data
    def encrypt(self, cipher, text):
        ciphertext = cipher.encrypt(text)
        return ciphertext

    #  Decrypt text and data
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

        # Tab
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 50, 620, 370))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.tab2 = QtWidgets.QWidget()
        self.tab2.setObjectName("tab2")

        # TextBrowser
        self.textBrowser = QtWidgets.QTextBrowser(self.tab)
        self.textBrowser.setGeometry(QtCore.QRect(10, 190, 595, 125))
        self.textBrowser.setObjectName("textBrowser")

        # TextEdit
        self.textEdit = QtWidgets.QTextEdit(self.tab)
        self.textEdit.setGeometry(QtCore.QRect(10, 25, 595, 125))
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

        # LineEdit
        self.lineEdit = QtWidgets.QLineEdit(self.tab2)
        self.lineEdit.setGeometry(QtCore.QRect(10, 25, 480, 25))
        self.lineEdit.setObjectName("lineEdit")

        # LineEdit2
        self.lineEdit_2 = QtWidgets.QLineEdit(self.tab2)
        self.lineEdit_2.setGeometry(QtCore.QRect(10, 190, 480, 25))
        self.lineEdit_2.setObjectName("lineEdit_2")

        # PushButton
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(12, 435, 145, 40))
        self.pushButton.setObjectName("pushButton")

        # PushButton2
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(169, 435, 145, 40))
        self.pushButton_2.setObjectName("pushButton_2")

        # PushButton3
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(326, 435, 145, 40))
        self.pushButton_3.setObjectName("pushButton_3")

        # PushButton4
        self.pushButton_4 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_4.setGeometry(QtCore.QRect(483, 435, 145, 40))
        self.pushButton_4.setObjectName("pushButton_4")

        # PushButton5
        self.pushButton_5 = QtWidgets.QPushButton(self.tab2)
        self.pushButton_5.setGeometry(QtCore.QRect(505, 25, 100, 25))
        self.pushButton_5.setObjectName("pushButton_5")

        # PushButton6
        self.pushButton_6 = QtWidgets.QPushButton(self.tab2)
        self.pushButton_6.setGeometry(QtCore.QRect(505, 190, 100, 25))
        self.pushButton_6.setObjectName("pushButton_6")

        # Label
        self.label = QtWidgets.QLabel(self.tab)
        self.label.setGeometry(QtCore.QRect(30, 5, 100, 15))
        self.label.setObjectName("label")

        # Label2
        self.label_2 = QtWidgets.QLabel(self.tab)
        self.label_2.setGeometry(QtCore.QRect(30, 170, 100, 15))
        self.label_2.setObjectName("label_2")

        # Label3
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(20, 20, 150, 15))
        self.label_3.setObjectName("label_3")

        # Label4
        self.label_4 = QtWidgets.QLabel(self.tab2)
        self.label_4.setGeometry(QtCore.QRect(30, 5, 200, 15))
        self.label_4.setObjectName("label_4")

        # Label5
        self.label_5 = QtWidgets.QLabel(self.tab2)
        self.label_5.setGeometry(QtCore.QRect(30, 170, 200, 15))
        self.label_5.setObjectName("label_5")

        # Label6
        self.label_6 = QtWidgets.QLabel(self.tab2)
        self.label_6.setGeometry(QtCore.QRect(30, 60, 500, 50))
        self.label_6.setObjectName("label_6")

        # Label7
        self.label_7 = QtWidgets.QLabel(self.tab2)
        self.label_7.setGeometry(QtCore.QRect(30, 225, 500, 50))
        self.label_7.setObjectName("label_7")

        # Label8
        self.label_8 = QtWidgets.QLabel(self.centralwidget)
        self.label_8.setGeometry(QtCore.QRect(505, 20, 125, 15))
        self.label_8.setObjectName("label_8")

        MainWindow.setCentralWidget(self.centralwidget)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        self.tabWidget.addTab(self.tab, "Input Text")
        self.tabWidget.addTab(self.tab2, "Input File")
        # print(self.tabWidget.currentIndex())

        # Connect Buttons
        self.pushButton.clicked.connect(lambda: self.encryptButton())
        self.pushButton.setShortcut("Ctrl+E")
        self.pushButton_2.clicked.connect(lambda: self.decryptButton())
        self.pushButton_2.setShortcut("Ctrl+D")
        self.pushButton_4.clicked.connect(lambda: self.exitProgram())
        self.pushButton_4.setShortcut("Ctrl+Q")
        self.pushButton_5.clicked.connect(
            lambda: self.showDialog(self.label_6, self.lineEdit))
        self.pushButton_6.clicked.connect(
            lambda: self.showDialog(self.label_7, self.lineEdit_2))

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))

        self.pushButton.setText(_translate("MainWindow", "Encrypt"))
        self.pushButton_2.setText(_translate("MainWindow", "Decrypt"))
        self.pushButton_3.setText(_translate("MainWindow", "Settings"))
        self.pushButton_4.setText(_translate("MainWindow", "Exit"))
        self.pushButton_5.setText(_translate("MainWindow", "Open"))
        self.pushButton_6.setText(_translate("MainWindow", "Open"))

        self.label.setText(_translate("MainWindow",
                                      "Source Text:"))
        self.label_2.setText(_translate("MainWindow",
                                        "Edited Text:"))
        self.label_3.setText(_translate("MainWindow",
                                        "Encryption Algorithm:"))
        self.label_4.setText(_translate("MainWindow",
                                        "File To Encrypt/Decrypt:"))
        self.label_5.setText(_translate("MainWindow",
                                        "Encrypted/Decrypted File:"))

    def exitProgram(self):
        sys.exit()

    def showDialog(self, label, lineEdit):
        fname = QtWidgets.QFileDialog.getOpenFileName(self.centralwidget,
                                                      'Open file',
                                                      '/home/ptfn')

        if fname[0]:
            lineEdit.setText(fname[0])
            size = self.humanSize(os.path.getsize(fname[0]))
            label_string = f"File Name: {fname[0]}\nFile Size: {size}"
            label.setText(label_string)

        else:
            label.setText("Error!")

    def humanSize(self, size):
        measurements = ["bytes", "KiB", "MiB", "GiB", "TiB"]

        for i in range(5):
            if size < 1000:
                break
            size /= 1000
        return f"{round(size, 2)} {measurements[i]}"

    def write_file(self, file, data):
        file_out = open(f'{file}', 'wb')
        file_out.write(data)
        file_out.close()

    def read_file(self, file):
        return open(f'{file}', 'rb').read()

    def write_data(self, name, nonce, ciphertext):
        file_out = open(f'{name}', 'wb')
        [file_out.write(x) for x in (nonce, ciphertext)]
        file_out.close()

    def read_data(self, name):
        file_in = open(f'{name}', 'rb')
        return [file_in.read(x) for x in (8, -1)]

    def encryptButton(self):
        try:
            text, ok = QtWidgets.QInputDialog.getText(None,
                                                      "Attention",
                                                      "Password",
                                                      QtWidgets.QLineEdit.Password)

            if ok and text:
                password = text

            # Collecting data from the widgets
            algorithm = self.comboBox.currentText()

            if self.tabWidget.currentIndex() == 0:
                text = self.textEdit.toPlainText().encode()
                # Clear data from the widget
                self.textBrowser.clear()
                self.textEdit.clear()
            else:
                text = self.read_file(self.lineEdit.text())
                self.lineEdit.clear()
                self.label_6.clear()

            nonce = get_random_bytes(8)

            if password != "" and text != "":
                # Generate cipher for encrypt
                cipher = self.crypto.generateCipher(password,
                                                    algorithm,
                                                    nonce)

                # Encrypt and measuring time
                start = time.time()
                ciphertext = self.crypto.encrypt(cipher, text)
                end = format(time.time() - start, ".10f")

                self.label_8.setText(f"Time: {end}")

                if self.tabWidget.currentIndex() == 0:
                    # Print ciphertext and nonce
                    self.textBrowser.append(b64encode(ciphertext).decode())
                    self.textBrowser.append(b64encode(nonce).decode())
                else:
                    self.write_data(self.lineEdit_2.text(),
                                    nonce,
                                    ciphertext)
                    self.lineEdit_2.clear()
                    self.label_7.clear()

        except UnboundLocalError:
            self.textBrowser.append("Did`n keep the password!")
        except Exception as e:
            print(e)
            self.textBrowser.append("Error encrypt!")

    def decryptButton(self):
        try:
            text, ok = QtWidgets.QInputDialog.getText(None,
                                                      "Attention",
                                                      "Password?",
                                                      QtWidgets.QLineEdit.Password)

            if ok and text:
                password = text

            # Collecting data from the widgets
            algorithm = self.comboBox.currentText()

            if self.tabWidget.currentIndex() == 0:
                text = self.textEdit.toPlainText()
                nonce = b64decode(text.split('\n')[1].encode())
                ciphertext = b64decode(text.split('\n')[0].encode())
                # Clear data from the widget
                self.textBrowser.clear()
                self.textEdit.clear()
            else:
                nonce, ciphertext = self.read_data(self.lineEdit.text())
                self.lineEdit.clear()
                self.label_6.clear()

            if password != "" and text != "":
                # Generate cipher for decrypt
                cipher = self.crypto.generateCipher(password,
                                                    algorithm,
                                                    nonce)

                # Decrypt and measuring time
                start = time.time()
                text = self.crypto.decrypt(cipher, ciphertext)
                end = format(time.time() - start, ".10f")

                self.label_8.setText(f"Time: {end}")

                if self.tabWidget.currentIndex() == 0:
                    # Print text
                    self.textBrowser.append(text.decode())
                else:
                    self.write_file(self.lineEdit_2.text(),
                                    text)
                    self.lineEdit_2.clear()
                    self.label_7.clear()

        except UnboundLocalError:
            self.textBrowser.append("Did`n keep the password!")
        except Exception as e:
            print(e)
            self.textBrowser.append("Error decrypt!")


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Window()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
