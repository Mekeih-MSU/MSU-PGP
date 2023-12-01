# MSU-PGP
WEBSITE: https://msu-pgp-a87ee849cce0.herokuapp.com/

FULL DOCUMENTATION: https://docs.google.com/document/d/1i65OtDzVGEYo1hSlPzEFQIuFQOa07WLEXMcyi36Gj4A/edit?usp=sharing

1. Introduction 
Welcome to MSU PGP! This application allows you to easily manage your PGP (Pretty Good Privacy) keys, securely communicate with your contacts, and protect your sensitive information.

2. Features 
Generate and manage your own asymmetric keys.
Store and manage your contact's public keys.
Encrypt and decrypt text with ease.
Sign messages.
Hash messages.

4. Getting Started
To generate asymmetric keys...
- Navigate to the "Your Keys" section.
- Click on "Add"
- Enter the key pair’s nickname.
- Click on "Generate New Keys."

Adding Contacts...
- Navigate to the "Contacts" section.
- Click on "Add"
- Enter the contact's name and their public key.
- Click "Save" to add the contact.

4. Encrypting Text
Copy the text you want to encrypt.
Navigate to the “Contacts” section.
Paste plaintext and submit.
You can now paste the encrypted text anywhere you like.

5. Decrypting Text <a name="decrypting-text"></a>
Copy the encrypted text.
Navigate to the “Your Keys” section.
Paste encrypted text and submit.
You can now paste the plaintext anywhere you like.

6. Security Considerations
Always use strong and unique passphrases to protect your private keys.
Regularly backup your keys and store them in a secure location.
Be cautious while sharing your public keys and verify the identity of your contacts.

7. Local Installation
- Clone repo.
- $ pip install virtualenv
- Create a virtual environment and name it env.
- $ env\Scripts\activate.bat
- install requirements.
- $ flask run.

8. References

Security
PGP (Pretty Good Privacy) Documentation: Comprehensive guide to PGP functionalities. 
https://web.pa.msu.edu/reference/pgpdoc1.html

Python-RSA Library Documentation: Details on Python-RSA integration in the PGP App. https://stuvel.eu/python-rsa-doc/

Database
MongoDB Documentation: Overview of MongoDB integration in the MSU PGP Web Application. https://www.mongodb.com/docs/

Code Implementation
PGP.py Module Source Code: Source code for PGP functionalities. 

app.py Module Source Code: Source code for key management and database interaction. 

User Interface
MSU PGP Web Application Design Documentation: Information on the user interface design. 
