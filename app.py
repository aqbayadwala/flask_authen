from flask import Flask, render_template, request, redirect, session, url_for, flash
import pymysql
import os
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_login import UserMixin, current_user
from flask_bcrypt import Bcrypt
import requests


app = Flask(__name__)
bcrypt = Bcrypt(app)

# configurations
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("MYSQL_URL")
app.config["SECRET_KEY"] = os.environ.get("SECRET")


# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# # Database connection mysql
# connection_db = pymysql.connect(
#     host=os.environ.get("MYSQLHOST"),
#     port=int(os.environ.get("MYSQLPORT")),
#     user=os.environ.get("MYSQLUSER"),
#     password=os.environ.get("MYSQLPASSWORD"),
#     database=os.environ.get("MYSQLDATABASE"),
# )


def db_connection(other_query, create_table=None, params=None):
    with pymysql.connect(
        host=os.environ.get("MYSQLHOST"),
        port=int(os.environ.get("MYSQLPORT")),
        user=os.environ.get("MYSQLUSER"),
        password=os.environ.get("MYSQLPASSWORD"),
        database=os.environ.get("MYSQLDATABASE"),
    ) as connection_db:
        cursor = connection_db.cursor()

        if create_table:
            cursor.execute(create_table)
        if params is None:
            cursor.execute(other_query)
        else:
            cursor.execute(other_query, params)

        data = cursor.fetchone()
        cursor.close()
        connection_db.commit()
        return data


mysql_queries = {
    "create_database_hifzapp": "CREATE DATABASE IF NOT EXISTS hifzapp",
    "create_users_table_query": """
            CREATE TABLE IF NOT EXISTS users (
                id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
                username CHAR(128) NOT NULL UNIQUE,
                password_hash CHAR(128) NOT NULL
            )
        """,
    "existing_user_query": "SELECT * FROM users WHERE username=%s",
}


# User Class
class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

    @classmethod
    def get(cls, user_id):
        user_query = "SELECT * FROM users WHERE id = %s"
        user_data = None

        user_data = db_connection(user_query, params=(user_id,))

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

        create_users_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
                username CHAR(128) NOT NULL UNIQUE,
                password_hash CHAR(128) NOT NULL
            )
        """

        recaptcha_response = request.form.get("g-recaptcha-response")
        recaptcha_secret = os.environ.get("RECAPTCHA_SECRET")
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            {"secret": recaptcha_secret, "response": recaptcha_response},
        )

        recaptcha_data = response.json()
        # print(recaptcha_data["success"])

        if not recaptcha_data["success"]:
            flash("reCAPTCHA verification failed. Please try again.", "error")
            return redirect("register")

        existing_user_query = "SELECT * FROM users WHERE username=%s"
        insert_user_query = (
            "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
        )
        existing_user_username = db_connection(
            existing_user_query, create_users_table_query, (username,)
        )

        if existing_user_username:
            flash("Username taken. Please choose a different username", "error")
            return redirect("register")

        hashed_password = bcrypt.generate_password_hash(password)
        decoded_hashd_password = hashed_password.decode("utf-8")
        # print("hash while register: ", decoded_hashd_password)
        db_connection(
            insert_user_query,
            create_users_table_query,
            params=(username, decoded_hashd_password),
        )

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

        create_users_table_query = """
            CREATE TABLE IF NOT EXISTS users (
                id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
                username CHAR(128) NOT NULL UNIQUE,
                password_hash CHAR(128) NOT NULL
            )
        """
        # Recaptcha verification
        recaptcha_response = request.form.get("g-recaptcha-response")
        recaptcha_secret = os.environ.get("RECAPTCHA_SECRET")
        response = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            {"secret": recaptcha_secret, "response": recaptcha_response},
        )

        recaptcha_data = response.json()
        if not recaptcha_data["success"]:
            flash("reCAPTCHA verification failed. Please try again.", "error")
            return redirect("login")

        user_query_username = "SELECT * FROM users WHERE username=%s"
        user_data = db_connection(
            user_query_username, create_users_table_query, (username_login,)
        )

        if user_data == None:
            flash("Invalid User", "error")
            return redirect("login")
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
            flash("Invalid User", "error")
            return redirect("login")

    return render_template("login.html")


# Dashboard route
@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    return render_template("dashboard.html")


# Add student route
@app.route("/add_student", methods=["GET", "POST"])
def add_student():
    if request.method == "POST":
        fullname = request.form["fullname"]
        darajah = request.form["std"]
        juz = request.form["currenthifz"]
        email = request.form["email"]
        create_students_table_query_mysql = """
            CREATE TABLE IF NOT EXISTS students (
                id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
                teacher_id SMALLINT(5) NOT NULL,
                fullname CHAR(128) NOT NULL,
                darajah CHAR(128) NOT NULL,
                juz SMALLINT(2) NOT NULL,
                email CHAR(128) DEFAULT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (teacher_id) REFERENCES users (id)
            )
        """

        insert_student_query = "INSERT INTO students (teacher_id, fullname, darajah, juz, email) VALUES (%s, %s, %s, %s, %s)"

        db_connection(
            insert_student_query,
            create_students_table_query_mysql,
            params=(current_user.id, fullname, darajah, juz, email),
        )

        add_success_msg = "Student added successfully."
        return render_template("add_student.html", add_success_msg=add_success_msg)
    return render_template("add_student.html")


# Hifz entry route
@app.route("/marks_entry", methods=["GET", "POST"])
def marks_entry():
    if request.method == "POST":
        student_name = request.form["student"]
        create_daily_entry_table_query = """
            CREATE TABLE IF NOT EXISTS daily_entry (
                entry_id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
                time_stamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                teacher_id SMALLINT(5), 
                student_id SMALLINT(5),
                murajaah_juz SMALLINT(2),
                murajaah_marks SMALLINT(2),
                juzhaali_from SMALLINT(3),
                juzhaali_to SMALLINT(3),
                juzhaali_marks SMALLINT(2),
                jadeed_surah VARCHAR(128),
                jadeed_ayah SMALLINT(3),
                remarks_parent TEXT DEFAULT NULL,
                remarks_student TEXT DEFAULT NULL
                FOREIGN KEY (teacher_id, student_id) REFERENCES students (teacher_id, student_id),
            )
        """
        fetch_teacher_id_query = "SELECT teacher_id FROM students WHERE fullname = %s"
        teacher_id = db_connection(
            fetch_teacher_id_query, params=(current_user.id, student_name)
        )

    return render_template("marks_entry.html")


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
