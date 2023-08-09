from flask import Flask, render_template, request, redirect
import psycopg2
import os
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_login import UserMixin
from bcrypt import gensalt, hashpw, checkpw
import bcrypt

app = Flask(__name__)

# configurations
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")


# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# Database Connection
connection_db = psycopg2.connect(
    host=os.environ.get("DB_HOST"),
    port=int(os.environ.get("DB_PORT")),
    user=os.environ.get("DB_USER"),
    password=os.environ.get("DB_PASSWORD"),
    database=os.environ.get("DB_NAME"),
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
        bytes_register = password.encode("utf-8")
        # print(password)-debug

        # create_table_query_mysql = """
        #     CREATE TABLE IF NOT EXISTS users (
        #         id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
        #         username CHAR(128) NOT NULL UNIQUE,
        #         pass_hash CHAR(128) NOT NULL
        #     )
        # """

        create_table_query_postgresql = """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username CHAR(255) NOT NULL UNIQUE,
                password_hash CHAR(255) NOT NULL
            )
        """

        existing_user_query = "SELECT * FROM users WHERE username=%s"
        existing_user_username = None

        cursor = connection_db.cursor()
        cursor.execute(create_table_query_postgresql)

        cursor.execute(existing_user_query, (username,))
        existing_user_username = cursor.fetchone()

        if existing_user_username:
            error_message = "Username taken. Please choose a different username"
            return render_template("register.html", error_message=error_message)

        salt = gensalt()
        hashed_password = hashpw(bytes_register, salt)
        decoded_hashd_password = hashed_password.decode("utf-8")

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
        bytes_login = password_login.encode("utf-8")

        # create_table_query_mysql = """
        #     CREATE TABLE IF NOT EXISTS users (
        #         id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
        #         username CHAR(128) NOT NULL UNIQUE,
        #         pass_hash CHAR(128) NOT NULL
        #     )
        # """

        create_table_query_postgresql = """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username CHAR(255) NOT NULL UNIQUE,
                password_hash CHAR(255) NOT NULL
            )
        """

        user_query = "SELECT * FROM users WHERE username=%s"
        user_data = None

        cursor = connection_db.cursor()
        cursor.execute(create_table_query_postgresql)
        cursor.execute(user_query, (username_login,))
        user_data = cursor.fetchone()
        hash = user_data[2]
        print(hash)
        print(bcrypt.__hash__)
        hash_bytes = hash.encode("utf-8")
        check = checkpw(bytes_login, hash_bytes)
        print(check)

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
