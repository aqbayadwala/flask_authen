from bcrypt import gensalt, checkpw, hashpw

from werkzeug.security import generate_password_hash, check_password_hash

password = "secret"
# salt = gensalt()
