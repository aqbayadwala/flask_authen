from bcrypt import gensalt, checkpw, hashpw

# from werkzeug import
password = "secret".encode("utf-8")
salt = gensalt()
hash = hashpw(password, salt)
check = checkpw(password, hash)
print("password: ", password)
print("salt: ", salt)
print("hash: ", hash)
print("check: ", check)
