from flask import Flask, render_template, request, session, redirect
from flask_session import Session
from flask_login import LoginManager, login_required, login_user, logout_user
from flask_login import UserMixin
import psycopg2
from bcrypt import gensalt, checkpw, hashpw


# instantiate app
app = Flask(__name__)

# app configuration
app.config["SECRET_KEY"] = "thisisasecretkey"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_PERMANENT"] = False
app.config[
    "DATABASE_URL"
] = "postgres://cadbay:QPUlLdN5FFUvqrEEzucfmzTT3DvnyQZ7@dpg-cj8v06geba7s738d419g-a.oregon-postgres.render.com/authen_t6ed"

# instantiate login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# Login Manager Callback
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


# Database connection object
connection_db = psycopg2.connect(
    host="dpg-cj8v06geba7s738d419g-a",
    user="cadbay",
    password="QPUlLdN5FFUvqrEEzucfmzTT3DvnyQZ7",
    database="authen_t6ed",
    port=5432,
)


# Define User Class
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    def get(cls, user_id):
        user_query = "SELECT * FROM users WHERE id = %s"
        user_data = None

        cursor = connection_db.cursor()
        cursor.execute(user_query, (user_id))
        user_data = cursor.fetchone()

        if user_data:
            return cls(id=user_data[0], username=user_data[1])

        return None


# Home Page Route
@app.route("/")
def index():
    return render_template("home.html")


# Function for executing SQL queries
def execute_sql_query(query, params=None):
    cursor = connection_db.cursor()
    cursor.execute(query, params)
    connection_db.commit()


# Registration Route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        print("password: ", password)

        create_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username CHAR(255) NOT NULL UNIQUE,
                password_hash CHAR(255) NOT NULL
            )
        """

        existing_user_query = "SELECT * FROM users WHERE username = %s"
        existing_user_username = None

        cursor = connection_db.cursor()
        cursor.execute(create_table_query)

        cursor.execute(existing_user_query, (username,))
        existing_user_username = cursor.fetchone()

        if existing_user_username:
            error_message = "Username taken. Please choose a different username"
            return render_template("register.html", error_message=error_message)

        password = password.encode("utf-8")
        salt = gensalt()
        hashed_password = hashpw(password, salt)

        insert_user_query = (
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
        )
        execute_sql_query(insert_user_query, (username, hashed_password))
        connection_db.commit()
        return render_template("registration_success.html")

    return render_template("register.html")


# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username_login = request.form["username"]
        password_login = request.form["password"]
        print("login password:", password_login)
        create_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username CHAR(255) NOT NULL UNIQUE,
                password_hash CHAR(255) NOT NULL
            )
        """

        user_query = "SELECT * FROM users WHERE username = %s"
        user_data = None

        cursor = connection_db.cursor()
        cursor.execute(create_table_query)
        cursor.execute(user_query, (username_login,))
        user_data = cursor.fetchone()
        hashed_check = user_data[2]
        encoded_hash = hashed_check.encode("utf-8")
        print(hashed_check)
        print(encoded_hash)
        # hashed_check = hashed_check.strip()
        # print(hashed_check)
        # print(user_data)
        password_login_enc = password_login.encode("utf-8")

        check = checkpw(password_login_enc, encoded_hash)
        print(check)
        if user_data and checkpw(password_login_enc, encoded_hash):
            user = User(id=user_data[0], username=user_data[1])
            login_user(user)
            return redirect("/dashboard")
        else:
            not_valid = "Invalid User"
            return render_template("login.html", not_valid=not_valid)
    return render_template("login.html")


# Dashboard Route
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    return render_template("dashboard.html")


# Logout Route
@app.route("/logout", methods=["GET", "POST"])
def logout():
    logout_user()
    return redirect("/")


# Run App

if __name__ == "__main__":
    app.run(debug=True)
    app.debug = True
