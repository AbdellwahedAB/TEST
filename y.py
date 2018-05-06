from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
import os, msvcrt, time

#Méthod pour la générations des Clefs RSA
def genKeys(code):
    key = RSA.generate(2048)
    #generation de clef RSA avec protection de fonction SCRYPT
    encrypted_key = key.exportKey(passphrase=code, pkcs=8, protection="scryptAndAES128-CBC")
    with open('Private.bin', 'wb') as f:
        f.write(encrypted_key)
        f.close()
    with open('Public.pem', 'wb') as f:
        f.write(key.publickey().export_key())
        f.close()

#Method pour l'encryption d'un fichier

def encrypt(f):
	#data = ce qui va etre ecrypté

    data = open(f).read().encode('utf-8')
    out_f = open(f + '.encrypted','wb')

    #creation du clef du session aléatoire
    rec_key = RSA.import_key(open("Public.pem").read())
    sess_key = get_random_bytes(16)

    #encryption du Clef du session
    cipher_rsa = PKCS1_OAEP.new(rec_key)
    enc_sess_key = cipher_rsa.encrypt(sess_key)

    #encryption du fichier avec AES
    cipher_aes = AES.new(sess_key,AES.MODE_EAX)
    cipher_text, tag = cipher_aes.encrypt_and_digest(data)

    #sauvegarder ce qui est encrypté + quelques informations pour le decryptage

    [out_f.write(x) for x in (enc_sess_key, cipher_aes.nonce, tag, cipher_text)]

    out_f.close()

#Method pour la decryption d'un fichier

def decrypt(f, code):
    in_f = open(f, 'rb')
    in_k = open('Private.bin','rb')

    #importer le key privée pour la décryption

    priv_key = RSA.import_key(in_k.read(), code)

    #extracter les informations pour le decryptage

    enc_sess_key, nonce, tag, ciphertext = \
        [in_f.read(x) for x in (priv_key.size_in_bytes(), 16, 16, -1)]
    
    #decrypter le clef du seesion

    cipher_rsa = PKCS1_OAEP.new(priv_key)
    sess_key = cipher_rsa.decrypt(enc_sess_key)

    #decryption du fichier avec les informations du decryptage extractés du ficher
    cipher_aes = AES.new(sess_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    #renommer et sauvegarder

    f_out = open(f[0:len(f) - 10], 'wb')
    f_out.write(data)
    in_f.close()
    f_out.close()

#Generation des Clefs RSA
#genKeys("TEST")
#Test == le mot pass pour les clefs
#changer le mot pass et effacer le "#" du commentaire avant de "genKeys(motpass)"
#et executer pour generer des nouveaux clefs RSA

path = os.getcwd()

while True:
	choice = input("what do you want to do? (D)ecrypt or (E)ncrypt or EXIT : ")
	choice = choice.upper()
	if choice == "D":
		#selectionner tous les fichiers qui ont l'extension '.encrypted' dans le dossier spécifié
		for file in os.listdir(path + "/calls/"):
			if file.endswith(".encrypted"):
                #Decrypter les fichiers avec l'extention ".encrypted"
				decrypt("./calls/" + file, 'TEST')
				os.remove("./calls/" + file)
	elif choice == "E":
		print ("Press enter to stop the encryption loop ")
    	#selectionner tous les fichiers qui ont l'extension ".txt" dans le dossier specifié
		while True:
			for file in os.listdir(path + "/calls/"):
				if file.endswith(".txt"):
					encrypt("./calls/" + file)
					#supprimer les fichiers qui ne sont pas encryptés
					os.remove("./calls/" + file)
			if msvcrt.kbhit():
				if msvcrt.getwche() == '\r':
					break
				time.sleep(0.1)
	elif choice == "EXIT":
		break  
	else :
		print(choice + ' is not an option')


    	