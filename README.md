# digitalSignature
Import libraries
```
from Crypto.PublicKey import RSA
import Crypto
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
import os

import sys
if sys.version_info < (3, 6):
    import sha3

import PySimpleGUI as sg
```

Functions
```
def readingFile():
    fileName = str((values["-IN-"])) #wybór pliku z okna programu
    file = open(fileName , "rb")
    hashedFile = SHA256.new(file.read()) 
    return hashedFile #zwracanie 256 bitowej wiadomości 



def createSignature():
    #generowanie klucza prywatnego i zapisanie go w folderze keyPair
    key = Crypto.PublicKey.RSA.generate(2048) 
    privateKey = key.export_key("PEM")
    privateKeyFilename = os.path.join("pairOfKeys", "key")
    with open(privateKeyFilename, "wb") as fd:
        fd.write(privateKey)
    os.chmod(privateKeyFilename, 0o600) #

    #generowanie klucza publicznego i zapisanie go w folderze keyPair
    publicKey = key.publickey().export_key("OpenSSH")
    publicKeyFilename = os.path.join("pairOfKeys", "keyPublic")
    with open(publicKeyFilename, "wb") as fd:
        fd.write(publicKey)
    os.chmod(publicKeyFilename, 0o600)

    privateKey = RSA.import_key(open('pairOfKeys\\key').read())
    hashedFile = readingFile() 
    signature = pkcs1_15.new(privateKey).sign(hashedFile) #tworzenie cyfrowego podpisu dla wybranego wcześniej pliku
    
    #zapisanie cyfrowego podpisu jako plik signature
    signFilename = os.path.join("signature")
    with open(signFilename, "wb") as fd:
        fd.write(signature)
    os.chmod(signFilename, 0o600)
    print("done")

def checkSignature():
    
    signPath = os.path.join("signature") 
    signatureToVerify = open(signPath, "rb").read() #pobranie pliku signature z folderu
    publicKey = RSA.import_key(open("pairOfKeys\\keyPublic").read()) #pobranie pliku keyPublic z folderu
    hashedFile = readingFile() #pobranie pliku, dla którego został wygenerowany podpis
    verifier = PKCS115_SigScheme(publicKey) #korzytanie z klasy PKCS115_SigScheme w celu weryfikacji podpisu

    #weryfikacja podpisu cyfrowego i wypisanie wyniku w oknie programu
    try:
        verifier.verify(hashedFile,signatureToVerify)
        print("Signature valid")
        output = "Signature valid"
        window['OUTPUT'].update(output)

    except:
        print("Signature invalid")
        output = "Signature invalid"
        window['OUTPUT'].update(output)
        
        
 ```

Simple GUI

```
sg.theme('DarkAmber')  #wybór motywu

layout = [  [[sg.T("")], [sg.Text("Choose a file: "), sg.Input(), sg.FileBrowse(key="-IN-")]],
            [sg.Button('Create signature'), sg.Button('Check signature'), sg.Button('Cancel')],
            [sg.Text("", size=(0, 1), key='OUTPUT')] ] #tworzenie layoutu


window = sg.Window('Digital Signature', layout) #tworzenie okna prostego interfejsu graficznego 


while True: #pętla działania programu
    event, values = window.read()
    if event == sg.WIN_CLOSED or event == 'Cancel':
        break
    elif event == 'Create signature':

        createSignature() #tworzenie podpisu cyfrowego 
        window['OUTPUT'].update('done')

        
    elif event == 'Check signature' :

        checkSignature() #weryfikacja podpisu cyfrowego


window.close() #zamknięcie okna programu
```
