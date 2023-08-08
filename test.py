from bcrypt import gensalt, checkpw, hashpw

from werkzeug.security import generate_password_hash, check_password_hash

password = "secret"
# salt = gensalt()
hash = generate_password_hash(password)
check = check_password_hash(hash, password)
print("password: ", password)
# print("salt: ", salt)
print("hash: ", hash)
print("check: ", check)
