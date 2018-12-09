import os, time, shutil, base64, stat
import ctypes, platform, sys, socket
from tkinter import *
from tkinter import filedialog
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

#you can edit your desired folder name here!
my_folder = "Important Files"

#set the window's poperties
os.system("mode con cols=70 lines=40")
ctypes.windll.kernel32.SetConsoleTitleW("Fernet Crypt")
time.sleep(2)

if not os.path.isdir(my_folder):
    try:
        print("Missing '%s' Directory ..."%my_folder)
        os.mkdir(my_folder)
        print("Creating the required directory, Please wait ...")
        time.sleep(3)
    except Exception as e:
        print(e)
        time.sleep(2)
        sys.exit()        

hostname = socket.gethostname()
host_ip = socket.gethostbyname(socket.gethostname())
pform = platform.system()

keygen = None
saltedkey = None
key = None

def generate_saltedkey_keygen(check):
    if check:
        try:
            sys.stdout.write(RESET)
            keygen = Fernet.generate_key()
            saltedkey = os.urandom(32)
            print("  Generating Keygen and a Salted Key ...")
            time.sleep(5)
            print("  Successfully Created a Keygen and a Salted Key.\n")
            sys.stdout.write(YELLOW)            
            print("  Keygen:      %s"%keygen)            
            print("  Salted Key:  %s\n"%saltedkey)
            #decode the key to utf-8
            keygen = keygen.decode("utf-8")
            #the loop aims to remove the b format and append in a list
            sltdky = []
            loop_attempt = 0
            for eachSalted in str(saltedkey):
                if loop_attempt > 0:
                    sltdky.append(eachSalted)
                loop_attempt = loop_attempt + 1
            #write the generated keygen to a file
            with open("keygen.keygen", "w+") as keygen_file:
                keygen_file.write(keygen)
            keygen_file.close()
            #write the generated salted key to a file
            with open("saltedkey.salted", "w+") as saltedkey_file:
                for eachSaltedKey in sltdky:
                    saltedkey_file.write(eachSaltedKey)
            saltedkey_file.close()
            sys.stdout.write(RESET)
            print("\n  Saving the keygen and salted key file, Please wait ...")
            time.sleep(5)
            print("  Successfully Save the Two Files")
            sys.stdout.write(CYAN)
            print("  Keygen.keygen Saves in:      {}".format(os.path.dirname(os.path.realpath("keygen.keygen"))+"\keygen.keygen"))
            print("  Saltedkey.salted Saves in:   {}".format(os.path.dirname(os.path.realpath("saltedkey.salted"))+"\saltedkey.salted"))
                  
        except Exception as e:
            print(e)
            time.sleep(2)

def create_key(check):
    if check:
        print("  Choose Hash Type:\n  A.) MD5\n  B.) SHA1\n  C.) SHA256\n  D.) SHA224\n  E.) SHA384\n  F.) SHA512\n")
        choose_type = input("  Select: ")
        if choose_type == 'A' or choose_type == 'a':
            generate_saltedkey_keygen(True)
            try:
                sys.stdout.write(RESET)
                with open("keygen.keygen","rb") as keygenfile:
                    keygen = keygenfile.read()
                keygenfile.close()
                with open("saltedkey.salted","rb") as saltedkeyfile:
                    saltedkey = saltedkeyfile.read()
                saltedkeyfile.close()
                kdfMD5 = PBKDF2HMAC(
                    algorithm = hashes.MD5(),
                    length = 32,
                    salt = saltedkey,
                    iterations = 100000,
                    backend = default_backend()
                    )
                key = base64.urlsafe_b64encode(kdfMD5.derive(keygen))
                print("\n  Creating the encryption key, Please wait ...")
                print("  Successfully Created The Key..\n")
                sys.stdout.write(YELLOW)
                print("  KEY: %s"%key)
                with open("key.key", "w+") as keyfile:
                    keyfile.write(str(key.decode("utf-8")))
                keyfile.close()            
                sys.stdout.write(RESET)
                print("\n  Saving your key to a key file, Please wait ...")
                time.sleep(3)
                sys.stdout.write(CYAN)
                print("  KEY File saves in:    {}".format(os.path.dirname(os.path.realpath("key.key"))+"\key.key"))
                sys.stdout.write(RESET)
                print("\n  -> SUCCESSFULLY CREATED THE ENCRYPTION KEY ... <-")
            except Exception as e:
                print(e)
                time.sleep(2)
        elif choose_type == 'B' or choose_type == 'b':
            generate_saltedkey_keygen(True)
            try:
                sys.stdout.write(RESET)
                with open("keygen.keygen","rb") as keygenfile:
                    keygen = keygenfile.read()
                keygenfile.close()
                with open("saltedkey.salted","rb") as saltedkeyfile:
                    saltedkey = saltedkeyfile.read()
                saltedkeyfile.close()
                kdfSHA1 = PBKDF2HMAC(
                    algorithm = hashes.SHA1(),
                    length = 32,
                    salt = saltedkey,
                    iterations = 100000,
                    backend = default_backend()
                    )
                key = base64.urlsafe_b64encode(kdfSHA1.derive(keygen))
                print("\n  Creating the encryption key, Please wait ...")
                print("  Successfully Created The Key..\n")
                sys.stdout.write(YELLOW)
                print("  KEY: %s"%key)
                with open("key.key", "w+") as keyfile:
                    keyfile.write(str(key.decode("utf-8")))
                keyfile.close()            
                sys.stdout.write(RESET)
                print("\n  Saving your key to a key file, Please wait ...")
                time.sleep(3)
                sys.stdout.write(CYAN)
                print("  KEY File saves in:    {}".format(os.path.dirname(os.path.realpath("key.key"))+"\key.key"))
                sys.stdout.write(RESET)
                print("\n  -> SUCCESSFULLY CREATED THE ENCRYPTION KEY ... <-")
            except Exception as e:
                print(e)
                time.sleep(2)
        elif choose_type == 'C' or choose_type == 'c':
            generate_saltedkey_keygen(True)
            try:
                sys.stdout.write(RESET)
                with open("keygen.keygen","rb") as keygenfile:
                    keygen = keygenfile.read()
                keygenfile.close()
                with open("saltedkey.salted","rb") as saltedkeyfile:
                    saltedkey = saltedkeyfile.read()
                saltedkeyfile.close()
                kdfSHA256 = PBKDF2HMAC(
                    algorithm = hashes.SHA256(),
                    length = 32,
                    salt = saltedkey,
                    iterations = 100000,
                    backend = default_backend()
                    )
                key = base64.urlsafe_b64encode(kdfSHA256.derive(keygen))
                print("\n  Creating the encryption key, Please wait ...")
                print("  Successfully Created The Key..\n")
                sys.stdout.write(YELLOW)
                print("  KEY: %s"%key)
                with open("key.key", "w+") as keyfile:
                    keyfile.write(str(key.decode("utf-8")))
                keyfile.close()            
                sys.stdout.write(RESET)
                print("\n  Saving your key to a key file, Please wait ...")
                time.sleep(3)
                sys.stdout.write(CYAN)
                print("  KEY File saves in:    {}".format(os.path.dirname(os.path.realpath("key.key"))+"\key.key"))
                sys.stdout.write(RESET)
                print("\n  -> SUCCESSFULLY CREATED THE ENCRYPTION KEY ... <-")
            except Exception as e:
                print(e)
                time.sleep(2)
        elif choose_type == 'D' or choose_type == 'd':
            generate_saltedkey_keygen(True)
            try:
                sys.stdout.write(RESET)
                with open("keygen.keygen","rb") as keygenfile:
                    keygen = keygenfile.read()
                keygenfile.close()
                with open("saltedkey.salted","rb") as saltedkeyfile:
                    saltedkey = saltedkeyfile.read()
                saltedkeyfile.close()
                kdfSHA224 = PBKDF2HMAC(
                    algorithm = hashes.SHA224(),
                    length = 32,
                    salt = saltedkey,
                    iterations = 100000,
                    backend = default_backend()
                    )
                key = base64.urlsafe_b64encode(kdfSHA224.derive(keygen))
                print("\n  Creating the encryption key, Please wait ...")
                print("  Successfully Created The Key..\n")
                sys.stdout.write(YELLOW)
                print("  KEY: %s"%key)
                with open("key.key", "w+") as keyfile:
                    keyfile.write(str(key.decode("utf-8")))
                keyfile.close()            
                sys.stdout.write(RESET)
                print("\n  Saving your key to a key file, Please wait ...")
                time.sleep(3)
                sys.stdout.write(CYAN)
                print("  KEY File saves in:    {}".format(os.path.dirname(os.path.realpath("key.key"))+"\key.key"))
                sys.stdout.write(RESET)
                print("\n  -> SUCCESSFULLY CREATED THE ENCRYPTION KEY ... <-")
            except Exception as e:
                print(e)
                time.sleep(2)
        elif choose_type == 'E' or choose_type == 'e':
            generate_saltedkey_keygen(True)
            try:
                sys.stdout.write(RESET)
                with open("keygen.keygen","rb") as keygenfile:
                    keygen = keygenfile.read()
                keygenfile.close()
                with open("saltedkey.salted","rb") as saltedkeyfile:
                    saltedkey = saltedkeyfile.read()
                saltedkeyfile.close()
                kdfSHA384 = PBKDF2HMAC(
                    algorithm = hashes.SHA384(),
                    length = 32,
                    salt = saltedkey,
                    iterations = 100000,
                    backend = default_backend()
                    )
                key = base64.urlsafe_b64encode(kdfSHA384.derive(keygen))
                print("\n  Creating the encryption key, Please wait ...")
                print("  Successfully Created The Key..\n")
                sys.stdout.write(YELLOW)
                print("  KEY: %s"%key)
                with open("key.key", "w+") as keyfile:
                    keyfile.write(str(key.decode("utf-8")))
                keyfile.close()            
                sys.stdout.write(RESET)
                print("\n  Saving your key to a key file, Please wait ...")
                time.sleep(3)
                sys.stdout.write(CYAN)
                print("  KEY File saves in:    {}".format(os.path.dirname(os.path.realpath("key.key"))+"\key.key"))
                sys.stdout.write(RESET)
                print("\n  -> SUCCESSFULLY CREATED THE ENCRYPTION KEY ... <-")
            except Exception as e:
                print(e)
                time.sleep(2)
        elif choose_type == 'F' or choose_type == 'f':
            generate_saltedkey_keygen(True)
            try:
                sys.stdout.write(RESET)
                with open("keygen.keygen","rb") as keygenfile:
                    keygen = keygenfile.read()
                keygenfile.close()
                with open("saltedkey.salted","rb") as saltedkeyfile:
                    saltedkey = saltedkeyfile.read()
                saltedkeyfile.close()
                kdfSHA512 = PBKDF2HMAC(
                    algorithm = hashes.SHA512(),
                    length = 32,
                    salt = saltedkey,
                    iterations = 100000,
                    backend = default_backend()
                    )
                key = base64.urlsafe_b64encode(kdfSHA512.derive(keygen))
                print("\n  Creating the encryption key, Please wait ...")
                print("  Successfully Created The Key..\n")
                sys.stdout.write(YELLOW)
                print("  KEY: %s"%key)
                with open("key.key", "w+") as keyfile:
                    keyfile.write(str(key.decode("utf-8")))
                keyfile.close()            
                sys.stdout.write(RESET)
                print("\n  Saving your key to a key file, Please wait ...")
                time.sleep(3)
                sys.stdout.write(CYAN)
                print("  KEY File saves in:    {}".format(os.path.dirname(os.path.realpath("key.key"))+"\key.key"))
                sys.stdout.write(RESET)
                print("\n  -> SUCCESSFULLY CREATED THE ENCRYPTION KEY ... <-")
            except Exception as e:
                print(e)
                time.sleep(2)

def encrypt_and_transfer_file(check):
    if check:
        #file directory where the files will be transfered and encrypted
        file_directory = r"{}\{}".format(os.path.dirname(os.path.realpath(my_folder)),my_folder)
    
        root = Tk()
        root.withdraw()
        root.fileName = filedialog.askopenfilenames(filetype = (("Text Files","*.txt"),("All Files","*.*")))

        if root.fileName != '':
            try:
                print("  The following file/s are ready to be transfered and encrypted.")
                sys.stdout.write(GREEN)
                for eachfiles in root.fileName:
                    print("  %s"%eachfiles)
                sys.stdout.write(YELLOW)
                input("\n  Press enter to continue...")
                sys.stdout.write(CYAN)
                keyfile_key = input('  Drag the generated key.key file here to Finish Encryption\n  Key File: ')            
                keyfile_key = keyfile_key.split('"')[1]
                print(keyfile_key)
                with open(keyfile_key, "rb") as kyfl:
                    key = kyfl.read()
                kyfl.close()                                
                sys.stdout.write(RESET)
                os.chdir(my_folder)
                for eachfiles in root.fileName:
                    time.sleep(0.5)                    
                    try:
                        try:
                            sys.stdout.write(YELLOW)
                            print("  Moving And Encrypting File: %s" % eachfiles)
                            shutil.move(eachfiles, file_directory)
                            
                            #file_to_be_encrypted
                            index = 0
                            file_arr = []
                            for eachf in eachfiles.split("/"):
                                index = index + 1
                                file_arr.append(eachf)                            
                            file_to_be_encrypted = file_arr[index - 1]
                            
                            #remove read-only att
                            os.chmod(file_to_be_encrypted, stat.S_IWRITE)                            
                            file = open(file_to_be_encrypted, "rb")
                            data = file.read()
                            file.close()

                            fernet = Fernet(key)
                            encrypted_data = fernet.encrypt(data)

                            enc_file = open(file_to_be_encrypted, "wb")
                            enc_file.write(encrypted_data)
                            enc_file.close()

                            os.rename(file_to_be_encrypted, file_to_be_encrypted + ".encrypted")
                            sys.stdout.write(GREEN)
                            print("  Moved and Encrypted Successfully!")
                            
                        except Exception as error:                        
                            print(error)
                    except Exception as e:
                        print(e)
                        print("  Cannot transfer the file or even encrypt it..")                
                os.chdir("../")
            except Exception as e:
                print(e)
                time.sleep(2)
        else:
            print("  No files selected..")

def decrypt_files(check):
    if check:
        try:
            sys.stdout.write(RESET)
            print("  The following files are ready to be decrypted.")
            os.chdir(my_folder)
            sys.stdout.write(GREEN)
            enc_files = []
            enc_file_dirs = []
            for dirname, dirnames, filenames in os.walk(os.getcwd()):
                for filename in filenames:
                    print("  %s"%os.path.join(dirname, filename))                    
                    enc_files.append(filename)
                    enc_file_dirs.append(os.path.join(dirname, filename))
            sys.stdout.write(YELLOW)
            input("\n  Press enter to continue ...")            
            sys.stdout.write(CYAN)
            keyfile_key = input('  Drag the used key.key file here to Finish Decryption\n  Key File: ')            
            keyfile_key = keyfile_key.split('"')[1]
            print(keyfile_key)
            with open(keyfile_key, "rb") as kyfl:
                key = kyfl.read()
            kyfl.close()                                
            sys.stdout.write(RESET)
            loop_count = 0
            for eachencfiles in enc_files:
                time.sleep(0.5)
                try:
                    sys.stdout.write(YELLOW)
                    print("  Decrypting File: %s"%enc_file_dirs[loop_count])
                    file_to_be_decrypted = eachencfiles

                    #remove read-only att
                    os.chmod(file_to_be_decrypted, stat.S_IWRITE)                            
                    file = open(file_to_be_decrypted, "rb")
                    data = file.read()
                    file.close()

                    fernet = Fernet(key)
                    decrypted_data = fernet.decrypt(data)

                    enc_file = open(file_to_be_decrypted, "wb")
                    enc_file.write(decrypted_data)
                    enc_file.close()

                    os.rename(file_to_be_decrypted, file_to_be_decrypted.split(".encrypted")[0])
                    sys.stdout.write(GREEN)
                    print("  Decrypted Successfully!")                    
                except Exception as e:
                    sys.stdout.write(RED)
                    print(e)
                    print("  Cannot decrypt the file %s, maybe because you used different key!" % eachencfiles)
                    
                loop_count = loop_count + 1
            os.chdir("../")
        except Exception as e:
            sys.stdout.write(RED)
            print(e)

def show_help_about(check):
    if check:
        try:
            sys.stdout.write(YELLOW)
            print("  ABOUT:")
            sys.stdout.write(GREEN)
            print("  The Fernet Crypt is a python script used to transfer a ")
            print("  selected files and encrypt them while in process. The  ")
            print("  program could also generate a random keygen and a      ")
            print("  salted key to be able to create a powerful encryption  ")
            print("  key in 6 different types of Hash Encryption.           ")
            sys.stdout.write(YELLOW)
            print("  NOTE")
            sys.stdout.write(GREEN)
            print("  When you use a key to encrypt a file/s, please don't   ")
            print("  delete or even loose that key which you have used to   ")
            print("  encrypt a file it's because it is also the key that    ")
            print("  you will going to use to decrypt your encrypted files  ")
            print("  If ever you have loose it, you could never retrieve    ")
            print("  your files again and forever..")
            print("\n")
            sys.stdout.write(YELLOW)
            print("  HELP:")
            sys.stdout.write(GREEN)
            print("  There will be no more help attachments or instructions  ")
            print("  here because the program is very easy to use and       ")
            print("  understand..")
        except Exception as e:
            sys.stdout.write(RED)
            print(e)

if str(platform.system()) == 'Windows':
    os.system('cls')
else:
    os.system('clear')

RED   = "\033[1;31m"
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"
BG_YELLOW = '\033[43m'
YELLOW = '\033[01;33m'
GREEN = "\033[01;32m"

#open the main banner
sys.stdout.write(YELLOW)
with open(r"Banner/Fernet Crypt.banner", "r") as fc_banner:
    print(fc_banner.read())
sys.stdout.write(GREEN)
print("  =================================================================  ")
print("                        PROGRAMMED BY: ARIEN                         ")
print("  =================================================================  ")
sys.stdout.write(GREEN)
print("  \n  Fernet Crypt python script use to encrypt selected files for some  ")
print("  privacy reasons and purposes. The program able to create key file  ")
print("  which was salted by a random generated key and also to be used for ")
print("  file encryption..\n")
print("  Hostname: %s"%hostname)
print("  Host IP: %s"%host_ip)
print("  Platform: %s"%pform)

while True:
    print("\n")
    sys.stdout.write(RESET)
    choice = input("  Select your choice below:\n    1.) Create Encryption Key\n    2.) Transfer files and encrypt\n    3.) Decrypt the Transfered files\n    4.) Help and About\n    5.) Exit\n\n  Enter your choice: ")

    if choice == '1':
        create_key(True)
    elif choice == '2':                
        encrypt_and_transfer_file(True)
    elif choice == '3':
        decrypt_files(True)
    elif choice == '4':
        show_help_about(True)
    elif choice == '5':
        sys.stdout.write(YELLOW)
        print("\n  Quitting ...")
        time.sleep(3)
        sys.exit(0)
