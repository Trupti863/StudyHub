
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_connection
from functools import wraps
import os
import uuid


app = Flask(__name__)

# Secret key for session management
app.secret_key = os.environ.get(
    "STUDYHUB_SECRET_KEY",
    "studyhub-development-key-change-before-deployment"
)

UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")
ALLOWED_EXTENSIONS = {"pdf"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# Check allowed file extension
def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# Check whether user is logged in
def login_required(route):
    @wraps(route)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        return route(*args, **kwargs)

    return wrapper


# SIGNUP
@app.route("/signup", methods=["GET", "POST"])
def signup():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            return render_template(
                "signup.html",
                error="Please fill in all fields."
            )

        if len(password) < 8:
            return render_template(
                "signup.html",
                error="Password must be at least 8 characters."
            )

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute(
                "SELECT id FROM users WHERE email = %s",
                (email,)
            )

            existing_user = cursor.fetchone()

            if existing_user:
                return render_template(
                    "signup.html",
                    error="This email is already registered."
                )

            hashed_password = generate_password_hash(password)

            cursor.execute(
                """
                INSERT INTO users (username, email, password)
                VALUES (%s, %s, %s)
                """,
                (username, email, hashed_password)
            )

            connection.commit()

        finally:
            cursor.close()
            connection.close()

        return redirect(url_for("login"))

    return render_template("signup.html")


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute(
                "SELECT * FROM users WHERE email = %s",
                (email,)
            )

            user = cursor.fetchone()

        finally:
            cursor.close()
            connection.close()

        if user and check_password_hash(user["password"], password):

            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["username"]

            return redirect(url_for("home"))

        return render_template(
            "login.html",
            error="Invalid email or password."
        )

    return render_template("login.html")


# LOGOUT
@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():

    session.clear()

    return redirect(url_for("login"))


# HOME - SHOW ALL USERS' NOTES
@app.route("/")
@login_required
def home():

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT notes.*, users.username AS owner_name
            FROM notes
            JOIN users ON notes.user_id = users.id
            ORDER BY notes.id DESC
            """
        )

        notes = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template("index.html", notes=notes)


# ADD NOTE
@app.route("/add", methods=["GET", "POST"])
@login_required
def add_note():

    if request.method == "POST":

        title = request.form.get("title", "").strip()
        subject = request.form.get("subject", "").strip()

        pdf_file = request.files.get("pdf_file")
        filename = None

        if not title or not subject:
            return render_template(
                "add_note.html",
                error="Title and subject are required."
            ), 400

        if pdf_file and pdf_file.filename:

            if not allowed_file(pdf_file.filename):
                return render_template(
                    "add_note.html",
                    error="Only PDF files are allowed."
                ), 400

            safe_name = secure_filename(pdf_file.filename)

            if not safe_name:
                return render_template(
                    "add_note.html",
                    error="Please choose a valid PDF filename."
                ), 400

            filename = str(uuid.uuid4()) + "_" + safe_name

            pdf_file.save(
                os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    filename
                )
            )

        connection = get_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO notes
                (title, subject, pdf_file, user_id)
                VALUES (%s, %s, %s, %s)
                """,
                (
                    title,
                    subject,
                    filename,
                    session["user_id"]
                )
            )

            connection.commit()

        except Exception:
            # Remove the uploaded file if saving the note fails
            if filename:
                file_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    filename
                )

                if os.path.exists(file_path):
                    os.remove(file_path)

            raise

        finally:
            cursor.close()
            connection.close()

        return redirect(url_for("home"))

    return render_template("add_note.html")


# EDIT NOTE - ONLY THE OWNER CAN EDIT
@app.route("/edit/<int:id>", methods=["GET", "POST"])
@login_required
def edit_note(id):

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT *
            FROM notes
            WHERE id = %s AND user_id = %s
            """,
            (id, session["user_id"])
        )

        note = cursor.fetchone()

        if not note:
            return "Note not found or you are not allowed to edit it.", 404

        if request.method == "POST":

            title = request.form.get("title", "").strip()
            subject = request.form.get("subject", "").strip()

            pdf_file = request.files.get("pdf_file")
            old_filename = note["pdf_file"]
            new_filename = old_filename

            if not title or not subject:
                return render_template(
                    "edit_note.html",
                    note=note,
                    error="Title and subject are required."
                ), 400

            if pdf_file and pdf_file.filename:

                if not allowed_file(pdf_file.filename):
                    return render_template(
                        "edit_note.html",
                        note=note,
                        error="Only PDF files are allowed."
                    ), 400

                safe_name = secure_filename(pdf_file.filename)

                if not safe_name:
                    return render_template(
                        "edit_note.html",
                        note=note,
                        error="Please choose a valid PDF filename."
                    ), 400

                new_filename = str(uuid.uuid4()) + "_" + safe_name

                pdf_file.save(
                    os.path.join(
                        app.config["UPLOAD_FOLDER"],
                        new_filename
                    )
                )

            try:
                cursor.execute(
                    """
                    UPDATE notes
                    SET title = %s,
                        subject = %s,
                        pdf_file = %s
                    WHERE id = %s AND user_id = %s
                    """,
                    (
                        title,
                        subject,
                        new_filename,
                        id,
                        session["user_id"]
                    )
                )

                connection.commit()

            except Exception:
                # Preserve the old PDF if the database update fails
                if new_filename != old_filename:
                    new_path = os.path.join(
                        app.config["UPLOAD_FOLDER"],
                        new_filename
                    )

                    if os.path.exists(new_path):
                        os.remove(new_path)

                raise

            # Remove the previous PDF after a successful update
            if new_filename != old_filename and old_filename:
                old_path = os.path.join(
                    app.config["UPLOAD_FOLDER"],
                    old_filename
                )

                if os.path.exists(old_path):
                    os.remove(old_path)

            return redirect(url_for("home"))

    finally:
        cursor.close()
        connection.close()

    return render_template("edit_note.html", note=note)


# DELETE NOTE - ONLY THE OWNER CAN DELETE
@app.route("/delete/<int:id>", methods=["POST"])
@login_required
def delete_note(id):

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT pdf_file
            FROM notes
            WHERE id = %s AND user_id = %s
            """,
            (id, session["user_id"])
        )

        note = cursor.fetchone()

        if not note:
            return "Note not found or you are not allowed to delete it.", 404

        cursor.execute(
            """
            DELETE FROM notes
            WHERE id = %s AND user_id = %s
            """,
            (id, session["user_id"])
        )

        connection.commit()

        if note["pdf_file"]:
            file_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                note["pdf_file"]
            )

            if os.path.exists(file_path):
                os.remove(file_path)

    finally:
        cursor.close()
        connection.close()

    return redirect(url_for("home"))


# SEARCH ALL SHARED NOTES
@app.route("/search")
@login_required
def search():

    keyword = request.args.get("keyword", "").strip()
    search_value = "%" + keyword + "%"

    connection = get_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT notes.*, users.username AS owner_name
            FROM notes
            JOIN users ON notes.user_id = users.id
            WHERE notes.title LIKE %s
               OR notes.subject LIKE %s
               OR users.username LIKE %s
            ORDER BY notes.id DESC
            """,
            (search_value, search_value, search_value)
        )

        notes = cursor.fetchall()

    finally:
        cursor.close()
        connection.close()

    return render_template(
        "index.html",
        notes=notes,
        keyword=keyword
    )


# VIEW SHARED PDF - ANY LOGGED-IN USER CAN READ IT
@app.route("/uploads/<filename>")
@login_required
def view_pdf(filename):

    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            """
            SELECT id
            FROM notes
            WHERE pdf_file = %s
            """,
            (filename,)
        )

        note = cursor.fetchone()

    finally:
        cursor.close()
        connection.close()

    if not note:
        return "PDF not found.", 404

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        filename
    )


# RUN APPLICATION
if __name__ == "__main__":
    app.run(debug=True)
