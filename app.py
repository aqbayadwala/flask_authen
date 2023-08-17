from flask import (
    Flask,
    render_template,
    request,
    redirect,
    session,
    url_for,
    flash,
    jsonify,
)
import pymysql
import os
from flask_login import LoginManager, login_user, login_required, logout_user
from flask_login import UserMixin, current_user
from flask_bcrypt import Bcrypt
import requests
from datetime import datetime


app = Flask(__name__)
bcrypt = Bcrypt(app)

# configurations
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("MYSQL_URL")
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")


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


def db_connection_only_first_index(other_query, create_table=None, params=None):
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

        data = cursor.fetchall()
        data = [item[0] for item in data]
        cursor.close()
        connection_db.commit()
        return data


def db_connection_all_indexes(other_query, create_table=None, params=None):
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

        data = cursor.fetchall()
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
@login_required
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
@login_required
def add_student():
    if request.method == "POST":
        fullname = request.form["fullname"]
        darajah = request.form["std"]
        its = request.form["itsno"]
        juz = int(request.form["currenthifz"])
        email = request.form["email"]
        create_students_table_query_mysql = """
            CREATE TABLE IF NOT EXISTS students (
                teacher_id SMALLINT(5) NOT NULL,
                ITS INT PRIMARY KEY,
                fullname CHAR(128) NOT NULL,
                darajah CHAR(128) NOT NULL,
                juz_c SMALLINT(2) NOT NULL,
                sanah CHAR(128) NOT NULL,
                email CHAR(128) DEFAULT NULL,
                created_at DATE DEFAULT (CURRENT_DATE),
                FOREIGN KEY (teacher_id) REFERENCES users (id)
            )
        """

        insert_student_query = "INSERT INTO students (teacher_id, ITS, fullname, darajah, juz_c, sanah, email) VALUES (%s, %s, %s, %s, %s, %s, %s)"

        if juz <= 5:
            sanah = "Sanah Ula"
        elif juz <= 12:
            sanah = "Sanah Saniyah"
        elif juz <= 21:
            sanah = "Sanah Salesah"
        elif juz <= 29:
            sanah = "Sanah Rabeah"
        else:
            sanah = "Sanah Khamis"

        db_connection(
            insert_student_query,
            create_students_table_query_mysql,
            params=(current_user.id, its, fullname, darajah, juz, sanah, email),
        )

        flash("Student added successfully.", "success")
        return redirect("add_student")
    return render_template("add_student.html")


# Hifz entry route
@app.route("/marks_entry", methods=["GET", "POST"])
@login_required
def marks_entry():
    if request.method == "POST":
        its = int(request.form["its"])
        name = request.form["student1"]
        sanah = request.form["sanah1"]
        murajaahjuz = int(request.form["murajaahjuz"])
        murajaahmarks = float(request.form["murajaahmarks"])
        if murajaahmarks == 0:
            murajaahmarks = None
        juzhaalimarks = float(request.form["juzhaalimarks"])
        if juzhaalimarks == 0:
            juzhaalimarks = None
        jadeedsurat = request.form["jadeedsurat"]
        if jadeedsurat == "":
            jadeedsurat = None
        else:
            jadeedsurat = jadeedsurat
        jadeedayat = request.form["jadeedayat"]
        jadeedpages = request.form["jadeedpages"]
        if jadeedayat == "":
            jadeedayat = None
        else:
            jadeedayat = int(request.form["jadeedayat"])

        if jadeedpages == "":
            jadeedpages = 0
        else:
            jadeedpages = int(request.form["jadeedpages"])
        for_parent = request.form["parent_remarks"]
        for_student = request.form["student_remarks"]

        create_daily_entry_table_query = """
            CREATE TABLE IF NOT EXISTS daily_entry (
                entry_id SMALLINT(5) AUTO_INCREMENT PRIMARY KEY,
                date_stamp DATE DEFAULT (CURRENT_DATE),
                teacher_id SMALLINT(5), 
                ITS INT,
                murajaah_juz CHAR(10),
                murajaah_marks DECIMAL(2,1),
                juzhaali_marks DECIMAL(2,1),
                jadeed_surat VARCHAR(128),
                jadeed_ayat SMALLINT(3),
                jadeed_pages SMALLINT(3),
                remarks_parent TEXT DEFAULT NULL,
                remarks_student TEXT DEFAULT NULL,
                FOREIGN KEY (teacher_id, ITS) REFERENCES students (teacher_id, ITS))
        """
        insert_marks_entry_query = "INSERT INTO daily_entry (teacher_id, ITS, murajaah_juz, murajaah_marks, juzhaali_marks, jadeed_surat, jadeed_ayat, jadeed_pages, remarks_parent, remarks_student) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s);"

        db_connection(
            insert_marks_entry_query,
            create_table=create_daily_entry_table_query,
            params=(
                current_user.id,
                its,
                murajaahjuz,
                murajaahmarks,
                juzhaalimarks,
                jadeedsurat,
                jadeedayat,
                jadeedpages,
                for_parent,
                for_student,
            ),
        )

        flash("Entry Done.", "success")
        return redirect("marks_entry")

    return render_template("marks_entry.html")


@app.route("/reports", methods=["GET", "POST"])
def reports():
    return render_template("reports.html")


@app.route("/api/fetch_student", methods=["GET"])
def fetch_student():
    fetch_teacher_id_query = "SELECT teacher_id FROM students WHERE ITS = %s"
    fetch_student_of_teacher_query = (
        "SELECT fullname, sanah FROM students WHERE teacher_id = %s AND ITS = %s"
    )
    its = int(request.args.get("its_number"))
    teacher_id = db_connection(fetch_teacher_id_query, params=(its))[0]
    student_db_data = db_connection(
        fetch_student_of_teacher_query, params=(teacher_id, its)
    )
    student_dict = {"fullname": student_db_data[0], "sanah": student_db_data[1]}
    return jsonify(student_dict)


@app.route("/api/fetch_surat", methods=["GET"])
def fetch_surat():
    fetch_surat_query = "SELECT surah_name FROM surat WHERE sanah_type = %s"
    fetch_ayat_query = (
        "SELECT from_ayat, to_ayat FROM surat WHERE surat_name = %s AND sanah_type = %s"
    )
    sanah = request.args.get("sanah_input")
    surat = request.args.get("surat_input")
    if sanah and not surat:
        print(sanah)
        surat_db_data = db_connection_only_first_index(
            fetch_surat_query, params=(sanah,)
        )
        # print(ajzaa_db_data)
        surat = {"surat_list": surat_db_data}
        print(surat)
        return jsonify(surat)
    # if sanah and surat:
    #     print(sanah)
    #     ayat_db_data = db_connection_only_first_index(fetch_ayat_query, params=(surat,))
    #     # print(ajzaa_db_data)
    #     ayaat = {"from_ayat": ayat_db_data[0], "to_ayat": ayat_db_data[1]}
    #     print(ayaat)
    #     return jsonify(ayaat)


@app.route("/api/fetch_report", methods=["GET"])
def fetch_report():
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    # print(start_date)
    if start_date == "":
        start_date = "2023-08-16"
    if end_date == "":
        end_date = datetime.now().strftime("%Y-%m-%d")
    # print(start_date)
    get_full_report_query = """
        WITH AvgCalculation AS (
            SELECT
                s.fullname,
                ROUND(AVG(d.murajaah_marks), 2) AS Murajaah,
                ROUND(AVG(d.juzhaali_marks), 2) AS Juzhaali,
                SUM(d.jadeed_pages) AS Jadeed
            FROM
                students s
            INNER JOIN daily_entry d ON s.ITS = d.ITS
            WHERE
                d.date_stamp >= %s AND d.date_stamp <= %s
            GROUP BY
                s.fullname
        )
        SELECT
            fullname,
            Murajaah,
            Juzhaali,
            CASE 
                WHEN Murajaah IS NULL OR Murajaah = 0 THEN Juzhaali
                WHEN Juzhaali IS NULL OR Juzhaali = 0 THEN Murajaah
                ELSE ROUND((Murajaah + Juzhaali) / 2, 2)
            END AS Average,
            Jadeed,
            RANK() OVER (ORDER BY (
                CASE 
                WHEN Murajaah IS NULL OR Murajaah = 0 THEN Juzhaali
                WHEN Juzhaali IS NULL OR Juzhaali = 0 THEN Murajaah
                ELSE ROUND((Murajaah + Juzhaali) / 2, 2)
                END) DESC) AS ranking
        FROM AvgCalculation
        ORDER BY ranking;
        """

    data = db_connection_all_indexes(
        get_full_report_query, params=(start_date, end_date)
    )

    result_list = []

    for row in data:
        fullname, murajaah, juzhaali, average, jadeed, rank = row
        result_list.append(
            {
                "rank": rank,
                "student_name": fullname,
                "murajaah": murajaah,
                "juzhaali": juzhaali,
                "average": average,
                "jadeed": jadeed,
            }
        )
    print(result_list)
    return jsonify(result_list)


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
