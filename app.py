from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
from pathlib import Path
import os
import uuid
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired


# =========================================================
# APP CONFIG
# =========================================================

app = Flask(__name__)

app.config["SECRET_KEY"] = "air-share-pro-change-this-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///airshare.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Maximum upload size: 500 MB
app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

db = SQLAlchemy(app)

# =========================================================
# FILE STORAGE
# =========================================================

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / "shared_files"

UPLOAD_FOLDER.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx",
    "ppt", "pptx", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "webp",
    "mp4", "mkv", "avi", "mov",
    "mp3", "wav",
    "zip", "rar", "7z"
}


# =========================================================
# DATABASE MODELS
# =========================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="user",
        nullable=False
    )

    can_upload = db.Column(
        db.Boolean,
        default=True
    )

    can_download = db.Column(
        db.Boolean,
        default=True
    )

    can_delete = db.Column(
        db.Boolean,
        default=False
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    original_name = db.Column(
        db.String(255),
        nullable=False
    )

    stored_name = db.Column(
        db.String(255),
        unique=True,
        nullable=False
    )

    size = db.Column(
        db.Integer,
        nullable=False
    )

    extension = db.Column(
        db.String(20)
    )

    uploaded_by = db.Column(
        db.String(80)
    )

    uploaded_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80)
    )

    action = db.Column(
        db.String(100)
    )

    filename = db.Column(
        db.String(255)
    )

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )


# =========================================================
# HELPERS
# =========================================================

def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def get_extension(filename):
    if "." in filename:
        return filename.rsplit(".", 1)[1].lower()
    return "file"


def format_size(size):
    if size < 1024:
        return f"{size} B"

    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"

    if size < 1024 * 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"

    return f"{size / (1024 * 1024 * 1024):.2f} GB"


@app.template_filter("filesize")
def filesize_filter(size):
    return format_size(size)


def current_user():
    user_id = session.get("user_id")

    if not user_id:
        return None

    return db.session.get(User, user_id)


def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        if not session.get("user_id"):
            flash("Please login first.", "warning")
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):

        user = current_user()

        if not user:
            return redirect(url_for("login"))

        if user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))

        return func(*args, **kwargs)

    return wrapper


def log_activity(action, filename=None):

    user = current_user()

    activity = Activity(
        username=user.username if user else "System",
        action=action,
        filename=filename
    )

    db.session.add(activity)
    db.session.commit()


# =========================================================
# LOGIN
# =========================================================

@app.route("/", methods=["GET"])
def index():

    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        user = User.query.filter_by(
            username=username
        ).first()

        if not user or not check_password_hash(
            user.password_hash,
            password
        ):
            flash(
                "Invalid username or password.",
                "danger"
            )

            return redirect(url_for("login"))

        session.clear()

        session["user_id"] = user.id
        session["role"] = user.role

        log_activity("Logged in")

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():

    log_activity("Logged out")

    session.clear()

    return redirect(url_for("login"))


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user = current_user()

    search = request.args.get(
        "search",
        ""
    ).strip()

    if search:

        files = File.query.filter(
            File.original_name.ilike(
                f"%{search}%"
            )
        ).order_by(
            File.uploaded_at.desc()
        ).all()

    else:

        files = File.query.order_by(
            File.uploaded_at.desc()
        ).all()

    total_files = File.query.count()

    total_size = db.session.query(
        db.func.sum(File.size)
    ).scalar() or 0

    recent_activity = Activity.query.order_by(
        Activity.created_at.desc()
    ).limit(10).all()

    return render_template(
        "dashboard.html",
        user=user,
        files=files,
        total_files=total_files,
        total_size=total_size,
        recent_activity=recent_activity,
        search=search
    )


# =========================================================
# UPLOAD
# =========================================================

@app.route("/upload", methods=["POST"])
@login_required
def upload():

    user = current_user()

    if not user.can_upload:
        flash(
            "You do not have upload permission.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    uploaded_files = request.files.getlist("files")

    if not uploaded_files:
        flash(
            "Please select at least one file.",
            "warning"
        )

        return redirect(url_for("dashboard"))

    success_count = 0

    for uploaded_file in uploaded_files:

        if not uploaded_file or not uploaded_file.filename:
            continue

        filename = secure_filename(
            uploaded_file.filename
        )

        if not filename:
            continue

        if not allowed_file(filename):

            flash(
                f"{filename} is not an allowed file type.",
                "danger"
            )

            continue

        extension = get_extension(filename)

        unique_name = (
            f"{uuid.uuid4().hex}_{filename}"
        )

        destination = UPLOAD_FOLDER / unique_name

        uploaded_file.save(destination)

        file_size = destination.stat().st_size

        new_file = File(
            original_name=filename,
            stored_name=unique_name,
            size=file_size,
            extension=extension,
            uploaded_by=user.username
        )

        db.session.add(new_file)

        activity = Activity(
            username=user.username,
            action="Uploaded",
            filename=filename
        )

        db.session.add(activity)

        success_count += 1

    db.session.commit()

    if success_count:

        flash(
            f"{success_count} file(s) uploaded successfully.",
            "success"
        )

    return redirect(url_for("dashboard"))


# =========================================================
# DOWNLOAD
# =========================================================

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):

    user = current_user()

    if not user.can_download:

        flash(
            "You do not have download permission.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    file = db.session.get(File, file_id)

    if not file:

        flash(
            "File not found.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    log_activity(
        "Downloaded",
        file.original_name
    )

    return send_from_directory(
        UPLOAD_FOLDER,
        file.stored_name,
        as_attachment=True,
        download_name=file.original_name
    )
# =========================================================
# SHARE FILE
# =========================================================

def share_serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"])


@app.route("/share/<int:file_id>")
@login_required
def share_file(file_id):

    file = db.session.get(File, file_id)

    if not file:
        flash("File not found.", "danger")
        return redirect(url_for("dashboard"))

    share_url = url_for(
        "download",
        file_id=file.id,
        _external=True
    )

    return render_template(
        "share.html",
        file=file,
        share_url=share_url
    )

# =========================================================
# PUBLIC SHARED DOWNLOAD
# =========================================================

@app.route("/shared/<token>")
def public_download(token):

    try:

        data = share_serializer().loads(
            token,
            max_age=24 * 60 * 60
        )

    except SignatureExpired:

        return """
        <h2 style="font-family:Arial;text-align:center;margin-top:100px">
            Share link expired
        </h2>
        """

    except BadSignature:

        return """
        <h2 style="font-family:Arial;text-align:center;margin-top:100px">
            Invalid share link
        </h2>
        """

    file = db.session.get(
        File,
        data.get("file_id")
    )

    if not file:

        return """
        <h2 style="font-family:Arial;text-align:center;margin-top:100px">
            File not found
        </h2>
        """

    return send_from_directory(
        UPLOAD_FOLDER,
        file.stored_name,
        as_attachment=True,
        download_name=file.original_name
    )

# =========================================================
# DELETE
# =========================================================

@app.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete_file(file_id):

    user = current_user()

    if not user.can_delete:

        flash(
            "You do not have delete permission.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    file = db.session.get(File, file_id)

    if not file:

        flash(
            "File not found.",
            "danger"
        )

        return redirect(url_for("dashboard"))

    file_path = UPLOAD_FOLDER / file.stored_name

    if file_path.exists():
        file_path.unlink()

    filename = file.original_name

    activity = Activity(
        username=user.username,
        action="Deleted",
        filename=filename
    )

    db.session.add(activity)

    db.session.delete(file)

    db.session.commit()

    flash(
        f"{filename} deleted successfully.",
        "success"
    )

    return redirect(url_for("dashboard"))


# =========================================================
# ADMIN PANEL
# =========================================================
@app.route("/admin")
@admin_required
def admin():

    users = User.query.order_by(
        User.created_at.desc()
    ).all()

    files = File.query.order_by(
        File.uploaded_at.desc()
    ).all()

    activities = Activity.query.order_by(
        Activity.created_at.desc()
    ).limit(20).all()

    total_storage = sum(
        file.size for file in files
    )

    return render_template(
        "admin.html",
        users=users,
        files=files,
        activities=activities,
        total_storage=total_storage
    )

# =========================================================
# CREATE USER
# =========================================================

@app.route("/admin/create-user", methods=["POST"])
@admin_required
def create_user():

    username = request.form.get(
        "username",
        ""
    ).strip()

    password = request.form.get(
        "password",
        ""
    )

    role = request.form.get(
        "role",
        "user"
    )

    if not username or not password:

        flash(
            "Username and password are required.",
            "danger"
        )

        return redirect(url_for("admin"))

    existing = User.query.filter_by(
        username=username
    ).first()

    if existing:

        flash(
            "Username already exists.",
            "danger"
        )

        return redirect(url_for("admin"))

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        role="admin" if role == "admin" else "user",
        can_upload=True,
        can_download=True,
        can_delete=False
    )

    db.session.add(new_user)

    db.session.commit()

    flash(
        f"User {username} created successfully.",
        "success"
    )

    return redirect(url_for("admin"))


# =========================================================
# DELETE USER
# =========================================================

@app.route(
    "/admin/delete-user/<int:user_id>",
    methods=["POST"]
)
@admin_required
def delete_user(user_id):

    user = db.session.get(User, user_id)

    if not user:

        flash(
            "User not found.",
            "danger"
        )

        return redirect(url_for("admin"))

    if user.role == "admin":

        flash(
            "Admin accounts cannot be deleted here.",
            "danger"
        )

        return redirect(url_for("admin"))

    username = user.username

    db.session.delete(user)

    db.session.commit()

    flash(
        f"User {username} deleted.",
        "success"
    )

    return redirect(url_for("admin"))


# =========================================================
# API-LIKE LOCAL STATS
# =========================================================

@app.route("/stats")
@login_required
def stats():

    total_files = File.query.count()

    total_size = db.session.query(
        db.func.sum(File.size)
    ).scalar() or 0

    return jsonify({
        "files": total_files,
        "size": format_size(total_size)
    })


# =========================================================
# ERROR HANDLERS
# =========================================================

@app.errorhandler(413)
def too_large(error):

    flash(
        "File is too large. Maximum allowed size is 500 MB.",
        "danger"
    )

    return redirect(url_for("dashboard"))


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def initialize_database():

    with app.app_context():

        db.create_all()

        # Create first admin automatically
        admin = User.query.filter_by(
            username="admin"
        ).first()

        if not admin:

            admin = User(
                username="admin",
                password_hash=generate_password_hash(
                    "admin123"
                ),
                role="admin",
                can_upload=True,
                can_download=True,
                can_delete=True
            )

            db.session.add(admin)

            db.session.commit()

            print("")
            print("=" * 50)
            print("AIR SHARE ADMIN CREATED")
            print("Username: admin")
            print("Password: admin123")
            print("=" * 50)
            print("")


# =========================================================
# START SERVER
# =========================================================
@app.route("/make-admin")
@login_required
def make_admin():

    user = current_user()

    user.role = "admin"

    db.session.commit()

    session["role"] = "admin"

    return redirect(url_for("dashboard"))
if __name__ == "__main__":

    initialize_database()

    print("")
    print("=" * 60)
    print("AIR SHARE PRO")
    print("=" * 60)
    print("Local:   http://127.0.0.1:5000")
    print("Network: http://YOUR-PC-IP:5000")
    print("=" * 60)
    print("")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )