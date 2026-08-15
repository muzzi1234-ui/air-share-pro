from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from functools import wraps
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
import os
import uuid
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from zeroconf import ServiceInfo, Zeroconf
import socket


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

    id = db.Column(
        db.Integer,
        primary_key=True
    )

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

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    # IMPORTANT:
    # Each network gets its own workspace
    network_id = db.Column(
        db.String(255),
        nullable=False,
        index=True
    )

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

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    network_id = db.Column(
        db.String(255),
        nullable=False,
        index=True
    )

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
# NETWORK IDENTIFICATION
# =========================================================

def get_client_ip():

    # Cloudflare sends the real visitor IP here
    cf_ip = request.headers.get("CF-Connecting-IP")

    if cf_ip:
        return cf_ip.strip()

    # Other reverse proxies
    forwarded = request.headers.get("X-Forwarded-For")

    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.remote_addr or "unknown"


def get_network_id():

    ip = get_client_ip()

    # -----------------------------------------------------
    # LOCAL LAN
    # -----------------------------------------------------

    # 192.168.x.x
    if ip.startswith("192.168."):

        parts = ip.split(".")

        if len(parts) == 4:
            return f"lan-192.168.{parts[2]}"


    # 10.x.x.x
    if ip.startswith("10."):

        parts = ip.split(".")

        if len(parts) == 4:
            return f"lan-10.{parts[1]}.{parts[2]}"


    # 172.16.x.x - 172.31.x.x
    if ip.startswith("172."):

        parts = ip.split(".")

        if len(parts) == 4:

            try:
                second = int(parts[1])

                if 16 <= second <= 31:
                    return f"lan-172.{parts[1]}.{parts[2]}"

            except ValueError:
                pass


    # -----------------------------------------------------
    # PUBLIC / CLOUDFLARE
    # -----------------------------------------------------

    # For Cloudflare/internet access we use the client
    # public IP as the workspace identity.
    #
    # Devices behind the same internet connection normally
    # share this public IP.
    #
    # Direct LAN access gives actual LAN isolation above.

    return f"public-{ip}"


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


# =========================================================
# GUEST USER
# =========================================================

def current_user():

    # No login required anymore.
    # This fake user keeps existing dashboard templates working.

    return SimpleNamespace(
        id=0,
        username="Guest",
        role="user",
        can_upload=True,
        can_download=True,
        can_delete=True
    )


def login_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        # LOGIN COMPLETELY DISABLED
        return func(*args, **kwargs)

    return wrapper


def admin_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):

        # Admin panel disabled for public Air Share mode.
        return func(*args, **kwargs)

    return wrapper


# =========================================================
# ACTIVITY
# =========================================================

def log_activity(action, filename=None):

    activity = Activity(
        network_id=get_network_id(),
        username="Guest",
        action=action,
        filename=filename
    )

    db.session.add(activity)
    db.session.commit()


# =========================================================
# HOME
# =========================================================

@app.route("/", methods=["GET"])
def index():

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# OLD LOGIN ROUTES
# =========================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    # Login is no longer required.
    return redirect(
        url_for("dashboard")
    )


@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/dashboard")
@login_required
def dashboard():

    network_id = get_network_id()

    search = request.args.get(
        "search",
        ""
    ).strip()


    if search:

        files = File.query.filter(
            File.network_id == network_id,
            File.original_name.ilike(
                f"%{search}%"
            )
        ).order_by(
            File.uploaded_at.desc()
        ).all()

    else:

        files = File.query.filter(
            File.network_id == network_id
        ).order_by(
            File.uploaded_at.desc()
        ).all()


    total_files = File.query.filter(
        File.network_id == network_id
    ).count()


    total_size = db.session.query(
        db.func.sum(File.size)
    ).filter(
        File.network_id == network_id
    ).scalar() or 0


    recent_activity = Activity.query.filter(
        Activity.network_id == network_id
    ).order_by(
        Activity.created_at.desc()
    ).limit(10).all()


    return render_template(
        "dashboard.html",
        user=current_user(),
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

    uploaded_files = request.files.getlist(
        "files"
    )


    if not uploaded_files:

        flash(
            "Please select at least one file.",
            "warning"
        )

        return redirect(
            url_for("dashboard")
        )


    network_id = get_network_id()

    success_count = 0


    for uploaded_file in uploaded_files:

        if not uploaded_file:
            continue

        if not uploaded_file.filename:
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


        extension = get_extension(
            filename
        )


        unique_name = (
            f"{uuid.uuid4().hex}_{filename}"
        )


        destination = (
            UPLOAD_FOLDER / unique_name
        )


        uploaded_file.save(
            destination
        )


        file_size = destination.stat().st_size


        new_file = File(

            network_id=network_id,

            original_name=filename,

            stored_name=unique_name,

            size=file_size,

            extension=extension,

            uploaded_by="Guest"
        )


        db.session.add(
            new_file
        )


        activity = Activity(

            network_id=network_id,

            username="Guest",

            action="Uploaded",

            filename=filename
        )


        db.session.add(
            activity
        )


        success_count += 1


    db.session.commit()


    if success_count:

        flash(
            f"{success_count} file(s) uploaded successfully.",
            "success"
        )


    return redirect(
        url_for("dashboard")
    )


# =========================================================
# DOWNLOAD
# =========================================================

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):

    network_id = get_network_id()


    file = File.query.filter(
        File.id == file_id,
        File.network_id == network_id
    ).first()


    if not file:

        flash(
            "File not found in this network.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


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

    return URLSafeTimedSerializer(
        app.config["SECRET_KEY"]
    )


@app.route("/share/<int:file_id>")
@login_required
def share_file(file_id):

    network_id = get_network_id()


    file = File.query.filter(
        File.id == file_id,
        File.network_id == network_id
    ).first()


    if not file:

        flash(
            "File not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    # Network ID is included inside token
    token = share_serializer().dumps({

        "file_id": file.id,

        "network_id": network_id
    })


    share_url = url_for(
        "public_download",
        token=token,
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
        <h2 style="
            font-family:Arial;
            text-align:center;
            margin-top:100px
        ">
            Share link expired
        </h2>
        """

    except BadSignature:

        return """
        <h2 style="
            font-family:Arial;
            text-align:center;
            margin-top:100px
        ">
            Invalid share link
        </h2>
        """


    network_id = get_network_id()


    # IMPORTANT:
    # Token network must match current network
    if data.get("network_id") != network_id:

        return """
        <h2 style="
            font-family:Arial;
            text-align:center;
            margin-top:100px
        ">
            This file belongs to another network.
        </h2>
        """


    file = File.query.filter(
        File.id == data.get("file_id"),
        File.network_id == network_id
    ).first()


    if not file:

        return """
        <h2 style="
            font-family:Arial;
            text-align:center;
            margin-top:100px
        ">
            File not found
        </h2>
        """


    log_activity(
        "Downloaded via share",
        file.original_name
    )


    return send_from_directory(

        UPLOAD_FOLDER,

        file.stored_name,

        as_attachment=True,

        download_name=file.original_name
    )


# =========================================================
# DELETE
# =========================================================

@app.route(
    "/delete/<int:file_id>",
    methods=["POST"]
)
@login_required
def delete_file(file_id):

    network_id = get_network_id()


    file = File.query.filter(

        File.id == file_id,

        File.network_id == network_id

    ).first()


    if not file:

        flash(
            "File not found in this network.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )


    file_path = (
        UPLOAD_FOLDER /
        file.stored_name
    )


    if file_path.exists():

        file_path.unlink()


    filename = file.original_name


    activity = Activity(

        network_id=network_id,

        username="Guest",

        action="Deleted",

        filename=filename
    )


    db.session.add(
        activity
    )


    db.session.delete(
        file
    )


    db.session.commit()


    flash(
        f"{filename} deleted successfully.",
        "success"
    )


    return redirect(
        url_for("dashboard")
    )


# =========================================================
# STATS
# =========================================================

@app.route("/stats")
@login_required
def stats():

    network_id = get_network_id()


    total_files = File.query.filter(
        File.network_id == network_id
    ).count()


    total_size = db.session.query(
        db.func.sum(File.size)
    ).filter(
        File.network_id == network_id
    ).scalar() or 0


    return jsonify({

        "files": total_files,

        "size": format_size(
            total_size
        )
    })


# =========================================================
# NETWORK INFO
# =========================================================

@app.route("/network-info")
def network_info():

    return jsonify({

        "network": get_network_id(),

        "client_ip": get_client_ip(),

        "message": "Air Share network workspace"
    })


# =========================================================
# ERROR HANDLER
# =========================================================

@app.errorhandler(413)
def too_large(error):

    flash(
        "File is too large. Maximum allowed size is 500 MB.",
        "danger"
    )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def initialize_database():

    with app.app_context():

        db.create_all()


# =========================================================
# LAN AUTO DISCOVERY
# =========================================================

zeroconf_instance = None


def start_lan_discovery():

    global zeroconf_instance


    hostname = socket.gethostname()


    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )


    try:

        sock.connect(
            ("8.8.8.8", 80)
        )

        local_ip = sock.getsockname()[0]


    except Exception:

        local_ip = "127.0.0.1"


    finally:

        sock.close()


    zeroconf_instance = Zeroconf()


    service_info = ServiceInfo(

        "_http._tcp.local.",

        "Air Share Pro._http._tcp.local.",

        addresses=[
            socket.inet_aton(local_ip)
        ],

        port=5000,

        properties={

            "name": "Air Share Pro",

            "type": "file-sharing",

            "url": f"http://{local_ip}:5000"
        },

        server=(
            f"airshare-"
            f"{hostname.lower()}.local."
        )
    )


    zeroconf_instance.register_service(
        service_info
    )


    print("")
    print("=" * 60)
    print("AIR SHARE LAN DISCOVERY")
    print("=" * 60)
    print(f"Device:       {hostname}")
    print(f"IP:           {local_ip}")
    print(
        f"Network URL:  http://{local_ip}:5000"
    )
    print(
        f"Device Name:  {hostname}:5000"
    )
    print("Service:      Air Share Pro")
    print("=" * 60)
    print("")


# =========================================================
# INITIALIZE DATABASE
# =========================================================

initialize_database()


# =========================================================
# START SERVER
# =========================================================

if __name__ == "__main__":

    start_lan_discovery()


    print("")
    print("=" * 60)
    print("AIR SHARE PRO")
    print("=" * 60)
    print(
        "Local:   http://127.0.0.1:5000"
    )
    print(
        "Network: http://YOUR-PC-IP:5000"
    )
    print("=" * 60)
    print("")


    app.run(

        host="0.0.0.0",

        port=5000,

        debug=False
    )