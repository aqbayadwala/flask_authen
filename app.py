from flask import Flask, render_template, request, session, redirect
from flask_session import Session
import pymysql
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_required, login_user, logout_user
from flask_login import UserMixin
import os

# instantiate app
app = Flask(__name__)

# app configuration
app.config["SECRET_KEY"] = "thisisasecretkey"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL")

# instantiate Session
Session(app)

# instantiate login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# Login Manager Callback
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


# Define User Class
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @classmethod
    def get(cls, user_id):
        user_query = "SELECT * FROM users WHERE id = %s"
        user_data = None

        with pymysql.connect(
            host="dpg-cj8lm0c5kgrc73b418s0-a",
            user="authen_9tnn_user",
            password="F8VZ73lmc0peyFXC4wjCpMH2HDDHjtQa",
            database="authen_9tnn",
            port=5432,
        ) as connection:
            cursor = connection.cursor()
            cursor.execute(user_query, user_id)
            user_data = cursor.fetchone()

        if user_data:
            return cls(id=user_data[0], username=user_data[1])

        return None


# Home Page Route
@app.route("/")
def index():
    return render_template("home.html")


# function needed in registration route named "execute_sql_query"
def execute_sql_query(query, params=None):
    connection = pymysql.connect(
        host="dpg-cj8lm0c5kgrc73b418s0-a",
        user="authen_9tnn_user",
        password="F8VZ73lmc0peyFXC4wjCpMH2HDDHjtQa",
        database="authen_9tnn",
        port=5432,
    )
    cursor = connection.cursor()
    cursor.execute(query, params)
    connection.commit()
    cursor.close()
    connection.close()


# Registration Route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        existing_user_query = "SELECT * FROM users WHERE username = %s"
        existing_user_username = None

        with pymysql.connect(
            host="dpg-cj8lm0c5kgrc73b418s0-a",
            user="authen_9tnn_user",
            password="F8VZ73lmc0peyFXC4wjCpMH2HDDHjtQa",
            database="authen_9tnn",
            port=5432,
        ) as connection:
            cursor = connection.cursor()
            cursor.execute(existing_user_query, username)
            existing_user_username = cursor.fetchone()

        if existing_user_username:
            error_message = "Username taken. Please choose a differnt username"
            return render_template("register.html", error_message=error_message)

        hashed_password = generate_password_hash(password)
        inser_user_query = "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
        execute_sql_query(inser_user_query, (username, hashed_password))
        return render_template("registratio_success.html")
    return render_template("register.html")


# Login Route
@app.route("/login", methods=["GET", "POST"])
def login():
    session = Session(app)

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user_query = "SELECT * FROM users WHERE username=%s"
        user_data = None

        with pymysql.connect(
            host="dpg-cj8lm0c5kgrc73b418s0-a",
            user="authen_9tnn_user",
            password="F8VZ73lmc0peyFXC4wjCpMH2HDDHjtQa",
            database="authen_9tnn",
            port=5432,
        ) as connection:
            cursor = connection.cursor()
            cursor.execute(user_query, username)
            user_data = cursor.fetchone()

        if user_data and check_password_hash(user_data[2], password):
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
