password manager
================

a local password manager with graphical interface, data encryption and integrated password generator.


addictions
----------
python 3.10 or higher and the following libraries:

    pip install customtkinter cryptography pyperclip --break-system-packages

on fedora, make sure you have tkinter installed:

    sudo dnf install python3-tkinter


start
-----
    python PasswordManager.py


functionality
------------
- upon first startup you are asked to create a master password (minimum 8 characters)
- the credentials are saved in an encrypted file in the user's home page
- real-time search by site or username
- ability to show/hide passwords
- copy the password to the clipboard with one click
- adding, editing and deleting entries
- password generator with adjustable length (from 8 to 48 characters)
- ability to change the master password at any time


safety
---------
- the master password is never saved in clear text
- only a hash of the master password is saved (pbkdf2 with sha256, 200,000 iterations)
- the encryption key is derived from the master password via pbkdf2 (480,000 iterations)
- the data is encrypted with fernet (aes-128-cbc + hmac-sha256)
- the encrypted file is saved in: ~/.password_manager_data.enc
- the salt is saved in: ~/.password_manager_salt
- the master hash is saved in: ~/.password_manager_hash


notes
----
- data files are created automatically on first startup
- if you forget the master password it is not possible to recover the data
- the pyperclip library requires xclip or xsel installed on linux to work:

    sudo dnf install xclip


<video width="320" height="240" controls>
  <source src="tutorial.mp4" type="video/mp4">
</video>
