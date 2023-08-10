from flask import Flask, render_template, request, redirect
import psycopg2
import pymysql
import os
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_login import UserMixin

from flask_bcrypt import Bcrypt

# from argon2 import PasswordHasher

app = Flask(__name__)
bcrypt = Bcrypt(app)
# ph = PasswordHasher()

# configurations
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("MYSQL_URL")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")


# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# # Database Connection MySQL
# connection_db = pymysql.connect(
#     host=os.environ.get("DB_HOST"),
#     port=int(os.environ.get("DB_PORT")),
#     user=os.environ.get("DB_USER"),
#     password=os.environ.get("DB_PASSWORD"),
#     database=os.environ.get("DB_NAME"),
# )

# Database connection postgresql
connection_db = pymysql.connect(
    host=os.environ.get("MYSQLHOST"),
    port=int(os.environ.get("MYSQLPORT")),
    user=os.environ.get("MYSQLUSER"),
    password=os.environ.get("MYSQLPASSWORD"),
    database=os.environ.get("MYSQLDATABASE"),
)


# User Class
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @classmethod
    def get(cls, user_id):
        user_query = "SELECT * FROM users WHERE id = %s"
        user_data = None

        cursor = connection_db.cursor()
        cursor.execute(user_query, (user_id,))
        user_data = cursor.fetchone()

        if user_data:
            return User(id=user_data[0], username=user_data[1])

        return None


# Index Route
@app.route("/")
def index():
    return render_template("index.html")


# Registration route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        # print(username)-debug
        password = request.form["password"]
        # bytes_register = password.encode("utf-8")
        # print(password)-debug

        create_table_query_mysql = """
            CREATE TABLE IF NOT EXISTS users (
                id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
                username CHAR(128) NOT NULL UNIQUE,
                password_hash CHAR(128) NOT NULL
            )
        """

        # create_table_query_postgresql = """
        #     CREATE TABLE IF NOT EXISTS users (
        #         id SERIAL PRIMARY KEY,
        #         username CHAR(255) NOT NULL UNIQUE,
        #         password_hash CHAR(255) NOT NULL
        #     )
        # """

        existing_user_query = "SELECT * FROM users WHERE username=%s"
        existing_user_username = None

        cursor = connection_db.cursor()
        cursor.execute(create_table_query_mysql)

        cursor.execute(existing_user_query, (username,))
        existing_user_username = cursor.fetchone()

        if existing_user_username:
            error_message = "Username taken. Please choose a different username"
            return render_template("register.html", error_message=error_message)

        hashed_password = bcrypt.generate_password_hash(password)
        decoded_hashd_password = hashed_password.decode("utf-8")
        # print("hash while register: ", decoded_hashd_password)

        insert_user_query = (
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
        )
        cursor.execute(insert_user_query, (username, decoded_hashd_password))
        connection_db.commit()
        return render_template("registration_success.html")

    return render_template("register.html")


# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_login = request.form["username"]
        password_login = request.form["password"]
        # hashed_incoming = bcrypt.generate_password_hash(password_login)
        # bytes_login = password_login.encode("utf-8")

        create_table_query_mysql = """
            CREATE TABLE IF NOT EXISTS users (
                id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
                username CHAR(128) NOT NULL UNIQUE,
                password_hash CHAR(128) NOT NULL
            )
        """

        # create_table_query_postgresql = """
        #     CREATE TABLE IF NOT EXISTS users (
        #         id SERIAL PRIMARY KEY,
        #         username CHAR(255) NOT NULL UNIQUE,
        #         password_hash CHAR(255) NOT NULL
        #     )
        # """

        user_query = "SELECT * FROM users WHERE username=%s"
        user_data = None

        cursor = connection_db.cursor()
        cursor.execute(create_table_query_mysql)
        cursor.execute(user_query, (username_login,))
        user_data = cursor.fetchone()
        hash = user_data[2]
        # print("Hash From DB: ", hash)
        # print("Password while logging in: ", password_login)
        # print("Login Password Hash: ", hashed_incoming)
        # hash_bytes = hash.encode("utf-8")
        # print(hash_bytes)
        check = bcrypt.check_password_hash(hash, password_login)
        # print(check)

        if user_data and check:
            user = User(id=user_data[0], username=user_data[1])
            login_user(user)
            return redirect("/dashboard")
        else:
            not_valid = "Invalid User"
            return render_template("login.html", not_valid=not_valid)

    return render_template("login.html")


# Dashboard route
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    return render_template("dashboard.html")


# Logout route
@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect("/login")


# User Loader
@login_manager.user_loader
def user_loader(user_id):
    return User.get(user_id)


if __name__ == "__main__":
    app.run(debug=True)
