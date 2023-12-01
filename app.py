from flask import Flask, render_template, url_for, request, redirect, session
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import pgp
import bcrypt
import secrets
import os

app = Flask(__name__)
app.config['MONGO_DBNAME'] = 'MSU_PGP_Database'
app.config['MONGO_URI'] = os.environ.get('MONGO_URI')
mongo = PyMongo(app)

# -- Session data --
app.secret_key = secrets.token_urlsafe(16)

@app.route("/")
def index():
    if session:
        return redirect('/key_library')
    
    return render_template('index.html')


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session:
        return redirect('/key_library')

    if request.method == "GET":
        return render_template('signup.html', already_user=False)
    
    if request.method == "POST":
        users = mongo.db.users
        #search for username in database
        existing_user = users.find_one({'name': request.form['username']})

        #if user not in database
        if not existing_user:
            username = request.form['username']
            #encode password for hashing
            password = (request.form['password']).encode("utf-8")
            #hash password
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password, salt)
            #add new user to database
            users.insert_one({'name': username, 'password': hashed})
            #store username in session
            session['username'] = request.form['username']
            return redirect('/key_library')

        else:
            return render_template('signup.html', already_user=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session:
        return redirect('/key_library')

    if request.method == "GET":
        return render_template('login.html', wrong_password=False, user_not_found=False)
    
    if request.method == "POST":
        users = mongo.db.users
        #search for username in database
        login_user = users.find_one({'name': request.form['username']})

        #if username in database
        if login_user:
            db_password = login_user['password']
            password = request.form['password'].encode("utf-8")
            #compare username in database to username submitted in form
            if bcrypt.checkpw(password, db_password):
                #store username in session
                session['username'] = request.form['username']
                return redirect('/key_library')
            else:
                return render_template('login.html', wrong_password=True, user_not_found=False)
        else:
            return render_template('login.html', wrong_password=False, user_not_found=True)


@app.route("/logout")
def logout():
    if not session:
        return redirect('/')
    
    #clear username from session data
    session.clear()
    return redirect('/')


@app.route("/key_library")
def key_library():
    if not session:
        return redirect('/')
    
    username = session['username']

    personal_keys = mongo.db.personal_keys
    user_personal_keys = personal_keys.find({"owner":username}).sort('entry_name')

    contact_keys = mongo.db.contact_keys
    user_contact_keys = contact_keys.find({"owner":username}).sort('entry_name')

    return render_template('key_library.html', username=username, user_personal_keys=user_personal_keys, user_contact_keys=user_contact_keys)


@app.route("/add_contact", methods=["GET", "POST"])
def add_contact():
    if not session:
        return redirect('/')
    
    if request.method == "GET":
        return render_template('add_contact.html', username = session['username'])
    
    if request.method == "POST":
        contact_keys = mongo.db.contact_keys
        contact_keys.insert_one({
            "owner": session['username'], 
            "entry_name": request.form['entry_name'], 
            "phone_number": request.form['phone_number'], 
            "email": request.form['email'], 
            "public_key": request.form['public_key']})

        return redirect('/key_library')


@app.route("/delete_contact/<key_id>", methods=["GET", "POST"])
def delete_contact(key_id):
    if not session:
        return redirect('/')
    
    if request.method == "POST":
        contact_keys = mongo.db.contact_keys
        contact_keys.delete_one({"_id":ObjectId(key_id)})

    return redirect('/key_library')


@app.route("/add_key", methods=["GET", "POST"])
def add_key():
    if not session:
        return redirect('/')
    
    if request.method == "GET":
        return render_template('add_key.html', username = session['username'])
    
    if request.method == "POST":
        personal_keys = mongo.db.personal_keys
        public_key, private_key = pgp.generate_asymmetric_keys()
        personal_keys.insert_one({
            "owner": session['username'], 
            "entry_name": request.form['entry_name'], 
            "public_key": public_key, 
            "private_key": private_key})

        return redirect('/key_library')


@app.route("/delete_key/<key_id>", methods=["GET", "POST"])
def delete_key(key_id):
    if not session:
        return redirect('/')
    
    if request.method == "POST":
        personal_keys = mongo.db.personal_keys
        personal_keys.delete_one({"_id":ObjectId(key_id)})

    return redirect('/key_library')


@app.route("/encrypt/<key_id>")
def encrypt(key_id):
    if not session:
        return redirect('/')
    
    username = session['username']

    personal_keys = mongo.db.personal_keys
    user_personal_keys = personal_keys.find({"owner":username}).sort('entry_name')

    contact_keys = mongo.db.contact_keys
    user_contact_keys = contact_keys.find({"owner":username}).sort('entry_name')

    return render_template('encrypt.html', 
                            username=username, 
                            key_id=key_id, 
                            user_personal_keys=user_personal_keys, 
                            user_contact_keys=user_contact_keys)


@app.route("/encryption_results/<key_id>", methods=["GET", "POST"])
def encryption_results(key_id):    
    username = session['username']
    encrypted_text = ""
    signature_verdict = False

    if request.method == "POST":
        plaintext = request.form['text']

        personal_keys = mongo.db.personal_keys
        form_id = request.form['signature_private_key_id']
        signature_private_key = ""
        if form_id:
            signature_private_key_id = personal_keys.find_one({"_id":ObjectId(request.form['signature_private_key_id'])})
            signature_private_key = signature_private_key_id['private_key']

        contact_keys = mongo.db.contact_keys
        encryption_public_key_id = contact_keys.find_one({"_id":ObjectId(key_id)})
        encryption_public_key = encryption_public_key_id['public_key']

        encrypted_text = pgp.encrypt_text(
            plain_text=plaintext,
            public_key=encryption_public_key)
        
        signature_verdict = False
        if encrypted_text and signature_private_key:
            signature = pgp.sign_text(
                plain_text=plaintext,
                private_key=signature_private_key)
            
            if signature: signature_verdict = True

            hash = mongo.db.hash
            hash.insert_one({
                "owner": username, 
                "ciphertext": plaintext, 
                "signature": signature})

    return render_template('encryption_results.html',
                            username=username,
                            encrypted_text=encrypted_text,
                            signature_verdict=signature_verdict)

@app.route("/decrypt/<key_id>")
def decrypt(key_id):
    if not session:
        return redirect('/')
    
    username = session['username']

    personal_keys = mongo.db.personal_keys
    user_personal_keys = personal_keys.find({"owner":username}).sort('entry_name')

    contact_keys = mongo.db.contact_keys
    user_contact_keys = contact_keys.find({"owner":username}).sort('entry_name')

    return render_template('decrypt.html', 
                            username=username, 
                            key_id=key_id, 
                            user_personal_keys=user_personal_keys, 
                            user_contact_keys=user_contact_keys)


@app.route("/decryption_results/<key_id>", methods=["GET", "POST"])
def decryption_results(key_id):
    username = session['username']
    decrypted_text = ""
    signature_verdict = False
    hash_verdict = False

    if request.method == "POST":
        ciphertext = request.form['text']

        personal_keys = mongo.db.personal_keys
        decryption_private_key_id = personal_keys.find_one({"_id":ObjectId(key_id)})
        decryption_private_key = decryption_private_key_id['private_key']

        contact_keys = mongo.db.contact_keys
        form_id = request.form['signature_public_key_id']
        signature_public_key = ""
        if form_id:
            signature_public_key_id = contact_keys.find_one({"_id":ObjectId(request.form['signature_public_key_id'])})
            signature_public_key = signature_public_key_id['public_key'] if signature_public_key_id else ""

        decrypted_text = pgp.decrypt_text(
            encrypted_text=ciphertext,
            private_key=decryption_private_key)
        
        signature_verdict = False
        hash_verdict = False
        sig_code = ""
        if decrypted_text:
            hash = mongo.db.hash
            all_ciphertexts = hash.find()
            for cipher_entry in all_ciphertexts:
                if decrypted_text == cipher_entry['ciphertext']:
                    hash_verdict = True
                    sig_code = cipher_entry['signature']
                    
            if signature_public_key:
                signature_verdict = pgp.verify_signature(
                    plain_text=decrypted_text,
                    public_key=signature_public_key,
                    signature=sig_code)

    return render_template('decryption_results.html',
                            username=username,
                            decrypted_text=decrypted_text, 
                            signature_verdict=signature_verdict,
                            hash_verdict=hash_verdict)


if __name__ == "__main__":
    app.run()
