import rsa
import base64

def generate_asymmetric_keys():
	public_key_raw, private_key_raw, = rsa.newkeys(1024)

	public_key_headers = public_key_raw.save_pkcs1().decode('utf-8')
	public_key_end_header = public_key_headers.replace("-----BEGIN RSA PUBLIC KEY-----", "")
	public_key = public_key_end_header.replace("-----END RSA PUBLIC KEY-----", "")

	private_key_headers = private_key_raw.save_pkcs1().decode('utf-8')
	private_key_end_header = private_key_headers.replace("-----BEGIN RSA PRIVATE KEY-----", "")
	private_key = private_key_end_header.replace("-----END RSA PRIVATE KEY-----", "")

	return public_key, private_key

def encrypt_text(plain_text:str, public_key:str) -> str:
	try:
		encrypted_text_bytes = rsa.encrypt(plain_text.encode(), rsa.PublicKey.load_pkcs1(format_public_key(public_key)))
		encrypted_text = base64.b64encode(encrypted_text_bytes).decode('utf-8')
		return encrypted_text
	except:
		return ""


def decrypt_text(encrypted_text:str, private_key:str) -> str:
	try:
		decrypted_text_bytes = rsa.decrypt(base64.b64decode(encrypted_text), rsa.PrivateKey.load_pkcs1(format_private_key(private_key)))
		decrypted_text = decrypted_text_bytes.decode()
		return decrypted_text
	except:
		return ""


def sign_text(plain_text:str, private_key:str) -> str:
	try:
		text_signature_bytes = rsa.sign(plain_text.encode(), rsa.PrivateKey.load_pkcs1(format_private_key(private_key)), "SHA-256")
		text_signature = base64.b64encode(text_signature_bytes).decode('utf-8')
		return text_signature
	except:
		return ""

def verify_signature(plain_text:str, public_key:str, signature:str) -> bool:
	try:
		signature_validation = rsa.verify(plain_text.encode(), base64.b64decode(signature), rsa.PublicKey.load_pkcs1(format_public_key(public_key)))
		return signature_validation == "SHA-256"
	except:
		return False

def format_public_key(key:str) -> str:
	final_key = "-----BEGIN RSA PUBLIC KEY-----\n" + key + "\n-----END RSA PUBLIC KEY-----"
	return final_key

def format_private_key(key:str) -> str:
	final_key = "-----BEGIN RSA PRIVATE KEY-----\n" + key + "\n-----END RSA PRIVATE KEY-----"
	return final_key
