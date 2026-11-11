from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_from_directory, jsonify
)
import sqlite3
import os
import uuid
from datetime import datetime
from functools import wraps
from urllib.parse import urlparse
import hmac
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename


app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "property_connect_development_key_change_this"
)

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024

DATABASE = os.path.join(app.root_path, "database.db")


OWNER_QR_IMAGE = "owner_qr.jpeg"


@app.context_processor
def inject_payment_qr():
    return {
        "owner_qr_url": url_for(
            "static",
            filename=OWNER_QR_IMAGE
        )
    }

def generate_csrf_token():
    """Return a stable CSRF token for the current session."""
    if "csrf_token" not in session:
        session["csrf_token"] = uuid.uuid4().hex
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


def _same_origin_request():
    """Compatibility check for older forms that do not yet send a CSRF token."""
    source = request.headers.get("Origin") or request.headers.get("Referer")
    if not source:
        return False

    try:
        source_host = urlparse(source).netloc.lower()
        request_host = request.host.lower()
        return bool(source_host and hmac.compare_digest(source_host, request_host))
    except (TypeError, ValueError):
        return False


def csrf_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if request.method == "POST":
            token = (
                request.form.get("csrf_token")
                or request.headers.get("X-CSRF-Token")
            )
            session_token = session.get("csrf_token")

            if token:
                valid_request = bool(
                    session_token
                    and hmac.compare_digest(str(token), str(session_token))
                )
            else:
                valid_request = _same_origin_request()

            if not valid_request:
                flash(
                    "Security check failed. Please refresh the page and try again.",
                    "error"
                )
                return redirect(request.referrer or url_for("dashboard"))

        return function(*args, **kwargs)
    return wrapper

UPLOAD_FOLDER = os.path.join(
    app.root_path, "static", "uploads", "properties"
)

PROFILE_UPLOAD_FOLDER = os.path.join(
    app.root_path, "static", "uploads", "profiles"
)

TENANT_DOCUMENT_FOLDER = os.path.join(
    app.root_path, "secure_uploads", "tenant_documents"
)

ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}

ALLOWED_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp"
}

ALLOWED_DOCUMENT_EXTENSIONS = {
    "pdf", "jpg", "jpeg", "png", "webp"
}

MAX_IMAGE_SIZE = 5 * 1024 * 1024
MAX_DOCUMENT_SIZE = 5 * 1024 * 1024

DOCUMENT_TYPES = [
    "ID Proof",
    "PAN Card",
    "Rental Agreement",
    "Income Proof",
    "Other"
]

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["PROFILE_UPLOAD_FOLDER"] = PROFILE_UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROFILE_UPLOAD_FOLDER, exist_ok=True)
os.makedirs(TENANT_DOCUMENT_FOLDER, exist_ok=True)


def get_db_connection():
    conn = sqlite3.connect(DATABASE, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 20000")
    return conn

def create_database():
    conn = get_db_connection()

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            mobile TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS properties (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            location TEXT NOT NULL,
            property_type TEXT NOT NULL,
            rent REAL NOT NULL,
            bedrooms INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(owner_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS property_images (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER NOT NULL,
            image_filename TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(property_id) REFERENCES properties(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS applications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER NOT NULL,
            tenant_id INTEGER NOT NULL,
            message TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(property_id) REFERENCES properties(id),
            FOREIGN KEY(tenant_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            property_id INTEGER,
            amount REAL NOT NULL,
            payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'Pending',
            payment_method TEXT DEFAULT 'QR',
            upi_reference TEXT,
            verified_by INTEGER,
            verified_at TEXT,
            rejection_reason TEXT,
            currency TEXT DEFAULT 'INR',
            FOREIGN KEY(tenant_id) REFERENCES users(id),
            FOREIGN KEY(property_id) REFERENCES properties(id),
            FOREIGN KEY(verified_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            property_id INTEGER,
            subject TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'Open',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(tenant_id) REFERENCES users(id),
            FOREIGN KEY(property_id) REFERENCES properties(id)
        );

        CREATE TABLE IF NOT EXISTS leases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER NOT NULL,
            tenant_id INTEGER NOT NULL,
            start_date TEXT,
            end_date TEXT,
            rent REAL,
            status TEXT DEFAULT 'Active',
            FOREIGN KEY(property_id) REFERENCES properties(id),
            FOREIGN KEY(tenant_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS maintenance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            property_id INTEGER,
            tenant_id INTEGER,
            issue TEXT NOT NULL,
            description TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(property_id) REFERENCES properties(id),
            FOREIGN KEY(tenant_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS tenant_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tenant_id INTEGER NOT NULL,
            document_type TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL UNIQUE,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(tenant_id) REFERENCES users(id)
                ON DELETE CASCADE
        );
    """)

    existing_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }

    user_columns = {
        "date_of_birth": "TEXT",
        "gender": "TEXT",
        "address": "TEXT",
        "city": "TEXT",
        "state": "TEXT",
        "pincode": "TEXT",
        "profile_image": "TEXT"
    }

    for column, column_type in user_columns.items():
        if column not in existing_columns:
            conn.execute(
                f"ALTER TABLE users ADD COLUMN {column} {column_type}"
            )

    conn.commit()
    conn.close()

def create_admin():
    admin_email = os.environ.get(
        "ADMIN_EMAIL", "admin@gmail.com"
    ).strip().lower()

    admin_password = os.environ.get("ADMIN_PASSWORD", "").strip()

    if not admin_password:
        return

    conn = get_db_connection()

    try:
        existing_admin = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (admin_email,)
        ).fetchone()

        if existing_admin is None:
            conn.execute("""
                INSERT INTO users
                (name, email, mobile, password_hash, role)
                VALUES (?, ?, ?, ?, ?)
            """, (
                "Administrator",
                admin_email,
                "",
                generate_password_hash(admin_password),
                "admin"
            ))
            conn.commit()
    finally:
        conn.close()

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            flash("Please login first!", "error")
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


def role_required(*roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):
            if not session.get("logged_in"):
                flash("Please login first!", "error")
                return redirect(url_for("login"))

            if session.get("user_role") not in roles:
                flash("You are not allowed to access this page!", "error")
                return redirect(url_for("dashboard"))

            return function(*args, **kwargs)
        return wrapper
    return decorator


def allowed_image(filename):
    if not filename or "." not in filename:
        return False
    extension = filename.rsplit(".", 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS


def validate_images(files):
    for image in files:
        if not image or not image.filename:
            continue

        safe_name = secure_filename(image.filename)
        if not allowed_image(safe_name):
            return "JPG, JPEG, PNG, WEBP photos mattum upload pannunga!"

        if image.mimetype not in ALLOWED_MIME_TYPES:
            return "Valid image files mattum upload pannunga!"

        image.seek(0, os.SEEK_END)
        size = image.tell()
        image.seek(0)

        if size > MAX_IMAGE_SIZE:
            return "Oru photo maximum 5 MB irukkanum!"

    return None


def save_property_images(conn, property_id, files):
    saved_paths = []
    for image in files:
        if not image or not image.filename:
            continue

        safe_name = secure_filename(image.filename)
        if "." not in safe_name:
            continue

        extension = safe_name.rsplit(".", 1)[1].lower()
        filename = f"{uuid.uuid4().hex}.{extension}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)

        image.save(filepath)
        saved_paths.append(filepath)

        conn.execute("""
            INSERT INTO property_images
            (property_id, image_filename)
            VALUES (?, ?)
        """, (property_id, filename))

    return saved_paths


def get_property_images(conn, property_id):
    rows = conn.execute("""
        SELECT image_filename
        FROM property_images
        WHERE property_id = ?
        ORDER BY id ASC
    """, (property_id,)).fetchall()
    return [row["image_filename"] for row in rows]


def delete_image_files(images):
    for image in images:
        filename = (
            image["image_filename"]
            if isinstance(image, sqlite3.Row)
            else image
        )
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        if os.path.isfile(filepath):
            try:
                os.remove(filepath)
            except OSError:
                app.logger.exception("Unable to delete image: %s", filename)


def valid_document_content(uploaded_file, extension):
    uploaded_file.seek(0)
    header = uploaded_file.read(12)
    uploaded_file.seek(0)

    if extension == "pdf":
        return header.startswith(b"%PDF")
    if extension in {"jpg", "jpeg"}:
        return header.startswith(b"\xff\xd8\xff")
    if extension == "png":
        return header.startswith(b"\x89PNG\r\n\x1a\n")
    if extension == "webp":
        return len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP"
    return False


def remove_tenant_document_file(filename):
    safe_filename = os.path.basename(filename)
    filepath = os.path.join(TENANT_DOCUMENT_FOLDER, safe_filename)
    if os.path.isfile(filepath):
        try:
            os.remove(filepath)
        except OSError:
            app.logger.exception("Unable to delete tenant document: %s", safe_filename)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        role = request.form.get("role", "")

        if not all([name, email, mobile, password, confirm_password, role]):
            return render_template("register.html", error="Please fill all fields!")

        if password != confirm_password:
            return render_template("register.html", error="Passwords do not match!")

        if len(password) < 8:
            return render_template("register.html", error="Password must contain at least 8 characters!")

        if role not in ["tenant", "owner"]:
            return render_template("register.html", error="Invalid account role!")

        conn = get_db_connection()
        try:
            conn.execute("""
                INSERT INTO users
                (name, email, mobile, password_hash, role)
                VALUES (?, ?, ?, ?, ?)
            """, (name, email, mobile, generate_password_hash(password), role))
            conn.commit()
            flash("Account created successfully! Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Email already registered!")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()
        try:
            user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        finally:
            conn.close()

        if user and check_password_hash(user["password_hash"], password):
            if user["role"] not in ["tenant", "owner", "admin"]:
                flash("Invalid account role!", "error")
                return redirect(url_for("login"))

            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["user_email"] = user["email"]
            session["user_role"] = user["role"]
            session["logged_in"] = True
            session["csrf_token"] = uuid.uuid4().hex

            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid email or password!", "error")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
    conn = get_db_connection()
    try:
        user = conn.execute("""
            SELECT id, name, email, mobile, role
            FROM users
            WHERE id = ?
        """, (session["user_id"],)).fetchone()
    finally:
        conn.close()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    if user["role"] == "owner":
        return render_template("owner_dashboard.html", user=user)
    if user["role"] == "tenant":
        return render_template("tenant_dashboard.html", user=user)
    if user["role"] == "admin":
        return render_template("admin_dashboard.html", user=user)

    session.clear()
    return redirect(url_for("login"))

@app.route("/profile")
@login_required
def profile():
    conn = get_db_connection()
    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        documents = []
        if user and user["role"] == "tenant":
            documents = conn.execute("""
                SELECT id, document_type, original_filename, uploaded_at
                FROM tenant_documents
                WHERE tenant_id = ?
                ORDER BY id DESC
            """, (session["user_id"],)).fetchall()
    finally:
        conn.close()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template("profile.html", user=user, documents=documents, document_types=DOCUMENT_TYPES)

@app.route("/tenant/documents/upload", methods=["POST"])
@role_required("tenant")
@csrf_required
def upload_tenant_document():
    document_type = request.form.get("document_type", "").strip()
    uploaded_file = request.files.get("document")

    if document_type not in DOCUMENT_TYPES:
        flash("Please select a valid document type!", "error")
        return redirect(url_for("profile"))

    if not uploaded_file or not uploaded_file.filename:
        flash("Please choose a document to upload!", "error")
        return redirect(url_for("profile"))

    safe_original_name = secure_filename(uploaded_file.filename)
    if not safe_original_name or "." not in safe_original_name:
        flash("Invalid document filename!", "error")
        return redirect(url_for("profile"))

    extension = safe_original_name.rsplit(".", 1)[1].lower()
    if extension not in ALLOWED_DOCUMENT_EXTENSIONS:
        flash("Upload PDF, JPG, JPEG, PNG or WEBP documents only!", "error")
        return redirect(url_for("profile"))

    uploaded_file.seek(0, os.SEEK_END)
    file_size = uploaded_file.tell()
    uploaded_file.seek(0)

    if file_size > MAX_DOCUMENT_SIZE:
        flash("Document maximum size is 5 MB!", "error")
        return redirect(url_for("profile"))

    if file_size == 0 or not valid_document_content(uploaded_file, extension):
        flash("File content does not match the selected file type!", "error")
        return redirect(url_for("profile"))

    stored_filename = f"{uuid.uuid4().hex}.{extension}"
    saved_path = os.path.join(TENANT_DOCUMENT_FOLDER, stored_filename)

    try:
        uploaded_file.save(saved_path)
        conn = get_db_connection()
        try:
            conn.execute("""
                INSERT INTO tenant_documents
                (tenant_id, document_type, original_filename, stored_filename)
                VALUES (?, ?, ?, ?)
            """, (session["user_id"], document_type, safe_original_name, stored_filename))
            conn.commit()
        finally:
            conn.close()
        flash("Document uploaded successfully!", "success")
    except Exception:
        remove_tenant_document_file(stored_filename)
        app.logger.exception("Tenant document upload failed")
        flash("Unable to upload document. Please try again!", "error")

    return redirect(url_for("profile"))

@app.route("/tenant/documents/download/<int:document_id>")
@role_required("tenant")
def download_tenant_document(document_id):
    conn = get_db_connection()
    try:
        document = conn.execute("""
            SELECT stored_filename, original_filename
            FROM tenant_documents
            WHERE id = ? AND tenant_id = ?
        """, (document_id, session["user_id"])).fetchone()
    finally:
        conn.close()

    if document is None:
        flash("Document not found!", "error")
        return redirect(url_for("profile"))

    return send_from_directory(
        TENANT_DOCUMENT_FOLDER,
        document["stored_filename"],
        as_attachment=True,
        download_name=document["original_filename"]
    )


@app.route("/tenant/documents/delete/<int:document_id>", methods=["POST"])
@role_required("tenant")
@csrf_required
def delete_tenant_document(document_id):
    conn = get_db_connection()
    try:
        document = conn.execute("""
            SELECT id, stored_filename
            FROM tenant_documents
            WHERE id = ? AND tenant_id = ?
        """, (document_id, session["user_id"])).fetchone()

        if document is None:
            flash("Document not found!", "error")
            return redirect(url_for("profile"))

        conn.execute("DELETE FROM tenant_documents WHERE id = ? AND tenant_id = ?", (document_id, session["user_id"]))
        conn.commit()
    finally:
        conn.close()

    remove_tenant_document_file(document["stored_filename"])
    flash("Document deleted successfully!", "success")
    return redirect(url_for("profile"))

@app.route("/edit_profile", methods=["GET", "POST"])
@login_required
@csrf_required
def edit_profile():
    user_id = session["user_id"]
    conn = get_db_connection()

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        mobile = request.form.get("mobile", "").strip()
        dob = request.form.get("date_of_birth", "").strip()
        gender = request.form.get("gender", "").strip()
        address = request.form.get("address", "").strip()
        city = request.form.get("city", "").strip()
        state = request.form.get("state", "").strip()
        pincode = request.form.get("pincode", "").strip()

        def profile_error(message):
            conn.close()
            flash(message, "error")
            return redirect(url_for("edit_profile"))

        if not name:
            return profile_error("Name cannot be empty!")
        if mobile and (not mobile.isdigit() or len(mobile) != 10):
            return profile_error("Enter a valid 10 digit mobile number!")
        if pincode and (not pincode.isdigit() or len(pincode) != 6):
            return profile_error("Enter a valid 6 digit pincode!")

        photo = request.files.get("profile_photo")
        new_profile_image = None
        old_profile_image = None

        if photo and photo.filename:
            safe_name = secure_filename(photo.filename)
            if not allowed_image(safe_name) or photo.mimetype not in ALLOWED_MIME_TYPES:
                return profile_error("Upload a valid JPG, JPEG, PNG or WEBP photo!")

            photo.seek(0, os.SEEK_END)
            photo_size = photo.tell()
            photo.seek(0)

            if photo_size > MAX_IMAGE_SIZE:
                return profile_error("Profile photo maximum size is 5 MB!")

            extension = safe_name.rsplit(".", 1)[1].lower()
            new_profile_image = f"{uuid.uuid4().hex}.{extension}"
            photo_path = os.path.join(PROFILE_UPLOAD_FOLDER, new_profile_image)
            photo.save(photo_path)

        try:
            old_user = conn.execute("SELECT profile_image FROM users WHERE id = ?", (user_id,)).fetchone()
            if old_user:
                old_profile_image = old_user["profile_image"]

            conn.execute("""
                UPDATE users
                SET name = ?, mobile = ?, date_of_birth = ?, gender = ?,
                    address = ?, city = ?, state = ?, pincode = ?,
                    profile_image = COALESCE(?, profile_image)
                WHERE id = ?
            """, (name, mobile, dob, gender, address, city, state, pincode, new_profile_image, user_id))
            conn.commit()
            session["user_name"] = name
        except Exception:
            conn.rollback()
            if new_profile_image:
                old_path = os.path.join(PROFILE_UPLOAD_FOLDER, new_profile_image)
                if os.path.isfile(old_path):
                    os.remove(old_path)
            app.logger.exception("Profile update failed")
            flash("Unable to update profile!", "error")
            return redirect(url_for("edit_profile"))
        finally:
            conn.close()

        if new_profile_image and old_profile_image:
            old_path = os.path.join(PROFILE_UPLOAD_FOLDER, old_profile_image)
            if os.path.isfile(old_path):
                try:
                    os.remove(old_path)
                except OSError:
                    pass

        flash("Profile updated successfully!", "success")
        return redirect(url_for("profile"))

    try:
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    finally:
        conn.close()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template("edit_profile.html", user=user)

@app.route("/owner/properties", methods=["GET", "POST"])
@role_required("owner")
@csrf_required
def owner_properties():
    conn = get_db_connection()

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        property_type = request.form.get("property_type", "").strip()
        rent_input = request.form.get("rent", "").strip()
        bedrooms_input = request.form.get("bedrooms", "").strip()
        images = request.files.getlist("images")

        try:
            rent = float(rent_input)
            bedrooms = int(bedrooms_input) if bedrooms_input else 0

            if not title or not location or not property_type or rent <= 0 or bedrooms < 0:
                raise ValueError

            image_error = validate_images(images)
            if image_error:
                flash(image_error, "error")
            else:
                saved_paths = []
                try:
                    cursor = conn.execute("""
                        INSERT INTO properties
                        (owner_id, title, description, location, property_type, rent, bedrooms)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (session["user_id"], title, description, location, property_type, rent, bedrooms))
                    property_id = cursor.lastrowid
                    saved_paths = save_property_images(conn, property_id, images)
                    conn.commit()
                    flash("Property added successfully!", "success")
                except Exception:
                    conn.rollback()
                    delete_image_files(saved_paths)
                    app.logger.exception("Property creation failed")
                    flash("Unable to add property. Please try again!", "error")
        except (ValueError, TypeError):
            flash("Please enter valid property details!", "error")

    try:
        property_rows = conn.execute("""
            SELECT * FROM properties WHERE owner_id = ? ORDER BY id DESC
        """, (session["user_id"],)).fetchall()

        properties = []
        for item in property_rows:
            data = dict(item)
            data["images"] = get_property_images(conn, item["id"])
            properties.append(data)
    finally:
        conn.close()

    return render_template("owner_properties.html", properties=properties)

@app.route("/owner/property/edit/<int:property_id>", methods=["GET", "POST"])
@role_required("owner")
@csrf_required
def edit_property(property_id):
    conn = get_db_connection()
    property_data = conn.execute("""
        SELECT * FROM properties WHERE id = ? AND owner_id = ?
    """, (property_id, session["user_id"])).fetchone()

    if property_data is None:
        conn.close()
        flash("Property not found!", "error")
        return redirect(url_for("owner_properties"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        location = request.form.get("location", "").strip()
        property_type = request.form.get("property_type", "").strip()
        rent_input = request.form.get("rent", "").strip()
        bedrooms_input = request.form.get("bedrooms", "").strip()
        images = request.files.getlist("images")

        try:
            rent = float(rent_input)
            bedrooms = int(bedrooms_input) if bedrooms_input else 0

            if not title or not location or not property_type or rent <= 0 or bedrooms < 0:
                raise ValueError

            image_error = validate_images(images)
            if image_error:
                flash(image_error, "error")
            else:
                saved_paths = []
                try:
                    conn.execute("""
                        UPDATE properties
                        SET title = ?, description = ?, location = ?,
                            property_type = ?, rent = ?, bedrooms = ?
                        WHERE id = ? AND owner_id = ?
                    """, (title, description, location, property_type, rent, bedrooms, property_id, session["user_id"]))
                    saved_paths = save_property_images(conn, property_id, images)
                    conn.commit()
                    conn.close()
                    flash("Property updated successfully!", "success")
                    return redirect(url_for("owner_properties"))
                except Exception:
                    conn.rollback()
                    delete_image_files(saved_paths)
                    app.logger.exception("Property update failed")
                    flash("Unable to update property. Please try again!", "error")
        except (ValueError, TypeError):
            flash("Please enter valid property details!", "error")

    images = get_property_images(conn, property_id)
    conn.close()
    return render_template("edit_property.html", property=property_data, images=images)


@app.route("/owner/property/delete/<int:property_id>", methods=["POST"])
@role_required("owner")
@csrf_required
def delete_property(property_id):
    conn = get_db_connection()
    property_data = conn.execute("""
        SELECT id FROM properties WHERE id = ? AND owner_id = ?
    """, (property_id, session["user_id"])).fetchone()

    if property_data is None:
        conn.close()
        flash("Property not found!", "error")
        return redirect(url_for("owner_properties"))

    images = conn.execute("""
        SELECT image_filename FROM property_images WHERE property_id = ?
    """, (property_id,)).fetchall()

    try:
        conn.execute("DELETE FROM applications WHERE property_id = ?", (property_id,))
        conn.execute("DELETE FROM leases WHERE property_id = ?", (property_id,))
        conn.execute("UPDATE payments SET property_id = NULL WHERE property_id = ?", (property_id,))
        conn.execute("UPDATE complaints SET property_id = NULL WHERE property_id = ?", (property_id,))
        conn.execute("UPDATE maintenance SET property_id = NULL WHERE property_id = ?", (property_id,))
        conn.execute("DELETE FROM property_images WHERE property_id = ?", (property_id,))
        conn.execute("DELETE FROM properties WHERE id = ? AND owner_id = ?", (property_id, session["user_id"]))
        conn.commit()
        delete_image_files(images)
        flash("Property deleted successfully!", "success")
    except sqlite3.Error:
        conn.rollback()
        app.logger.exception("Property deletion failed")
        flash("Unable to delete property. Please try again!", "error")
    finally:
        conn.close()

    return redirect(url_for("owner_properties"))

@app.route("/properties")
@role_required("tenant")
def view_properties():
    conn = get_db_connection()
    location = request.args.get("location", "").strip()
    property_type = request.args.get("property_type", "").strip()
    min_rent_input = request.args.get("min_rent", "").strip()
    max_rent_input = request.args.get("max_rent", "").strip()

    query = """
        SELECT properties.*, users.name AS owner_name
        FROM properties
        JOIN users ON properties.owner_id = users.id
        WHERE 1=1
    """
    params = []
    min_rent, max_rent = None, None

    if location:
        query += " AND properties.location LIKE ?"
        params.append(f"%{location}%")
    if property_type:
        query += " AND properties.property_type = ?"
        params.append(property_type)

    if min_rent_input:
        try:
            min_rent = float(min_rent_input)
            if min_rent < 0:
                raise ValueError
            query += " AND properties.rent >= ?"
            params.append(min_rent)
        except ValueError:
            min_rent_input = ""

    if max_rent_input:
        try:
            max_rent = float(max_rent_input)
            if max_rent < 0:
                raise ValueError
            query += " AND properties.rent <= ?"
            params.append(max_rent)
        except ValueError:
            max_rent_input = ""

    if min_rent is not None and max_rent is not None and min_rent > max_rent:
        property_rows = []
    else:
        query += " ORDER BY properties.id DESC"
        property_rows = conn.execute(query, params).fetchall()

    properties = []
    for item in property_rows:
        data = dict(item)
        data["images"] = get_property_images(conn, item["id"])
        properties.append(data)

    property_types = conn.execute("""
        SELECT DISTINCT property_type FROM properties
        WHERE property_type IS NOT NULL AND property_type != ''
        ORDER BY property_type
    """).fetchall()

    conn.close()
    return render_template(
        "properties.html",
        properties=properties,
        property_types=property_types,
        location=location,
        selected_type=property_type,
        min_rent=min_rent_input,
        max_rent=max_rent_input
    )


@app.route("/apply/<int:property_id>", methods=["POST"])
@role_required("tenant")
@csrf_required
def apply_property(property_id):
    conn = get_db_connection()
    property_data = conn.execute("SELECT id FROM properties WHERE id = ?", (property_id,)).fetchone()

    if property_data is None:
        conn.close()
        flash("Property not found!", "error")
        return redirect(url_for("view_properties"))

    existing = conn.execute("""
        SELECT id FROM applications
        WHERE property_id = ? AND tenant_id = ?
    """, (property_id, session["user_id"])).fetchone()

    if existing:
        flash("You have already applied for this property!", "error")
    else:
        message = request.form.get("message", "").strip()
        conn.execute("""
            INSERT INTO applications (property_id, tenant_id, message)
            VALUES (?, ?, ?)
        """, (property_id, session["user_id"], message))
        conn.commit()
        flash("Application submitted successfully!", "success")

    conn.close()
    return redirect(url_for("view_properties"))

@app.route("/owner/application/<int:application_id>/<action>", methods=["POST"])
@role_required("owner")
@csrf_required
def update_application(application_id, action):
    if action not in ["Accepted", "Rejected"]:
        flash("Invalid application action!", "error")
        return redirect(url_for("owner_section", section="applications"))

    conn = get_db_connection()
    application = conn.execute("""
        SELECT applications.id
        FROM applications
        JOIN properties ON applications.property_id = properties.id
        WHERE applications.id = ? AND properties.owner_id = ?
    """, (application_id, session["user_id"])).fetchone()

    if application is None:
        conn.close()
        flash("Application not found!", "error")
        return redirect(url_for("owner_section", section="applications"))

    conn.execute("UPDATE applications SET status = ? WHERE id = ?", (action, application_id))
    conn.commit()
    conn.close()

    flash("Application " + action.lower() + " successfully!", "success")
    return redirect(url_for("owner_section", section="applications"))


@app.route("/owner/lease/add", methods=["POST"])
@role_required("owner")
@csrf_required
def add_lease():
    owner_id = session["user_id"]
    property_id = request.form.get("property_id", type=int)
    tenant_id = request.form.get("tenant_id", type=int)
    start_date = request.form.get("start_date", "").strip()
    end_date = request.form.get("end_date", "").strip()
    rent_input = request.form.get("rent", "").strip()

    if not all([property_id, tenant_id, start_date, end_date, rent_input]):
        flash("Please fill all lease details!", "error")
        return redirect(url_for("owner_section", section="lease"))

    try:
        start_obj = datetime.strptime(start_date, "%Y-%m-%d")
        end_obj = datetime.strptime(end_date, "%Y-%m-%d")
        rent = float(rent_input)
        if end_obj < start_obj or rent <= 0:
            raise ValueError
    except ValueError:
        flash("Enter valid lease dates and rent amount!", "error")
        return redirect(url_for("owner_section", section="lease"))

    conn = get_db_connection()
    try:
        property_data = conn.execute("""
            SELECT id FROM properties WHERE id = ? AND owner_id = ?
        """, (property_id, owner_id)).fetchone()

        tenant = conn.execute("""
            SELECT id FROM users WHERE id = ? AND role = 'tenant'
        """, (tenant_id,)).fetchone()

        if property_data is None or tenant is None:
            flash("Invalid property or tenant selected!", "error")
            return redirect(url_for("owner_section", section="lease"))

        existing_lease = conn.execute("""
            SELECT id FROM leases
            WHERE property_id = ? AND LOWER(status) = 'active'
              AND NOT (end_date < ? OR start_date > ?)
        """, (property_id, start_date, end_date)).fetchone()

        if existing_lease:
            flash("This property already has an overlapping active lease!", "error")
            return redirect(url_for("owner_section", section="lease"))

        conn.execute("""
            INSERT INTO leases (property_id, tenant_id, start_date, end_date, rent, status)
            VALUES (?, ?, ?, ?, ?, 'Active')
        """, (property_id, tenant_id, start_date, end_date, rent))
        conn.commit()
        flash("Lease agreement created successfully!", "success")
    except Exception:
        conn.rollback()
        app.logger.exception("Lease creation failed")
        flash("Unable to create lease!", "error")
    finally:
        conn.close()

    return redirect(url_for("owner_section", section="lease"))


@app.route("/owner/lease/<int:lease_id>/<status>", methods=["POST"])
@role_required("owner")
@csrf_required
def update_lease_status(lease_id, status):
    if status not in ["Active", "Expired", "Terminated"]:
        flash("Invalid lease status!", "error")
        return redirect(url_for("owner_section", section="lease"))

    conn = get_db_connection()
    try:
        lease = conn.execute("""
            SELECT leases.id FROM leases
            JOIN properties ON leases.property_id = properties.id
            WHERE leases.id = ? AND properties.owner_id = ?
        """, (lease_id, session["user_id"])).fetchone()

        if lease is None:
            flash("Lease not found or access denied!", "error")
            return redirect(url_for("owner_section", section="lease"))

        conn.execute("UPDATE leases SET status = ? WHERE id = ?", (status, lease_id))
        conn.commit()
        flash("Lease status updated to " + status + "!", "success")
    finally:
        conn.close()

    return redirect(url_for("owner_section", section="lease"))

@app.route("/tenant/complaint/add", methods=["POST"])
@role_required("tenant")
@csrf_required
def add_complaint():
    tenant_id = session["user_id"]
    property_id = request.form.get("property_id", type=int)
    subject = request.form.get("subject", "").strip()
    description = request.form.get("description", "").strip()

    if not property_id or not subject:
        flash("Please select a property and enter complaint subject!", "error")
        return redirect(url_for("tenant_section", section="complaints"))

    conn = get_db_connection()
    try:
        active_lease = conn.execute("""
            SELECT id FROM leases
            WHERE tenant_id = ? AND property_id = ? AND LOWER(status) = 'active'
            ORDER BY id DESC LIMIT 1
        """, (tenant_id, property_id)).fetchone()

        if active_lease is None:
            flash("You can submit complaints only for your active leased property!", "error")
            return redirect(url_for("tenant_section", section="complaints"))

        conn.execute("""
            INSERT INTO complaints (tenant_id, property_id, subject, description, status)
            VALUES (?, ?, ?, ?, 'Open')
        """, (tenant_id, property_id, subject, description))
        conn.commit()
        flash("Complaint submitted successfully!", "success")
    finally:
        conn.close()

    return redirect(url_for("tenant_section", section="complaints"))


@app.route("/tenant/maintenance/add", methods=["POST"])
@role_required("tenant")
@csrf_required
def add_maintenance():
    tenant_id = session["user_id"]
    property_id = request.form.get("property_id", type=int)
    issue = request.form.get("issue", "").strip()
    description = request.form.get("description", "").strip()

    if not property_id or not issue:
        flash("Please select a property and enter the maintenance issue!", "error")
        return redirect(url_for("tenant_section", section="maintenance"))

    conn = get_db_connection()
    try:
        active_lease = conn.execute("""
            SELECT id FROM leases
            WHERE tenant_id = ? AND property_id = ? AND LOWER(status) = 'active'
            ORDER BY id DESC LIMIT 1
        """, (tenant_id, property_id)).fetchone()

        if active_lease is None:
            flash("You can submit maintenance requests only for your active leased property!", "error")
            return redirect(url_for("tenant_section", section="maintenance"))

        conn.execute("""
            INSERT INTO maintenance (property_id, tenant_id, issue, description, status)
            VALUES (?, ?, ?, ?, 'Pending')
        """, (property_id, tenant_id, issue, description))
        conn.commit()
        flash("Maintenance request submitted successfully!", "success")
    finally:
        conn.close()

    return redirect(url_for("tenant_section", section="maintenance"))


@app.route("/owner/maintenance/<int:maintenance_id>/<status>", methods=["POST"])
@role_required("owner")
@csrf_required
def update_maintenance_status(maintenance_id, status):
    if status not in ["Pending", "In Progress", "Completed", "Rejected"]:
        flash("Invalid maintenance status!", "error")
        return redirect(url_for("owner_section", section="maintenance"))

    conn = get_db_connection()
    try:
        maintenance_record = conn.execute("""
            SELECT maintenance.id FROM maintenance
            JOIN properties ON maintenance.property_id = properties.id
            WHERE maintenance.id = ? AND properties.owner_id = ?
        """, (maintenance_id, session["user_id"])).fetchone()

        if maintenance_record is None:
            flash("Maintenance request not found or access denied!", "error")
            return redirect(url_for("owner_section", section="maintenance"))

        conn.execute("UPDATE maintenance SET status = ? WHERE id = ?", (status, maintenance_id))
        conn.commit()
        flash("Maintenance status updated to " + status + "!", "success")
    finally:
        conn.close()

    return redirect(url_for("owner_section", section="maintenance"))

@app.route("/delete_payment/<int:payment_id>", methods=["POST"])
@login_required
@csrf_required
def delete_payment(payment_id):
    conn = get_db_connection()
    user_id = session["user_id"]
    role = session["user_role"]

    try:
        if role == "admin":
            conn.execute("DELETE FROM payments WHERE id = ?", (payment_id,))
        elif role == "owner":
            conn.execute("""
                DELETE FROM payments WHERE id = ? AND property_id IN (
                    SELECT id FROM properties WHERE owner_id = ?
                )
            """, (payment_id, user_id))
        elif role == "tenant":
            conn.execute("DELETE FROM payments WHERE id = ? AND tenant_id = ?", (payment_id, user_id))

        conn.commit()
        flash("Payment history deleted successfully!", "success")
    finally:
        conn.close()

    return redirect(request.referrer or url_for("dashboard"))


@app.route("/delete_complaint/<int:complaint_id>", methods=["POST"])
@login_required
@csrf_required
def delete_complaint(complaint_id):
    conn = get_db_connection()
    user_id = session["user_id"]
    role = session["user_role"]

    try:
        if role == "admin":
            conn.execute("DELETE FROM complaints WHERE id = ?", (complaint_id,))
        elif role == "owner":
            conn.execute("""
                DELETE FROM complaints WHERE id = ? AND property_id IN (
                    SELECT id FROM properties WHERE owner_id = ?
                )
            """, (complaint_id, user_id))
        elif role == "tenant":
            conn.execute("DELETE FROM complaints WHERE id = ? AND tenant_id = ?", (complaint_id, user_id))

        conn.commit()
        flash("Complaint deleted successfully!", "success")
    finally:
        conn.close()

    return redirect(request.referrer or url_for("dashboard"))


@app.route("/delete_maintenance/<int:maintenance_id>", methods=["POST"])
@login_required
@csrf_required
def delete_maintenance(maintenance_id):
    conn = get_db_connection()
    user_id = session["user_id"]
    role = session["user_role"]

    try:
        if role == "admin":
            conn.execute("DELETE FROM maintenance WHERE id = ?", (maintenance_id,))
        elif role == "owner":
            conn.execute("""
                DELETE FROM maintenance WHERE id = ? AND property_id IN (
                    SELECT id FROM properties WHERE owner_id = ?
                )
            """, (maintenance_id, user_id))
        elif role == "tenant":
            conn.execute("DELETE FROM maintenance WHERE id = ? AND tenant_id = ?", (maintenance_id, user_id))

        conn.commit()
        flash("Maintenance request deleted successfully!", "success")
    finally:
        conn.close()

    return redirect(request.referrer or url_for("dashboard"))

@app.route("/owner/<section>")
@role_required("owner")
def owner_section(section):
    allowed_sections = ["applications", "payments", "complaints", "tenants", "lease", "maintenance", "reports"]
    if section not in allowed_sections:
        flash("Page not found!", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    owner_id = session["user_id"]
    payment_properties, lease_properties, lease_tenants = [], [], []

    try:
        if section == "applications":
            records = conn.execute("""
                SELECT applications.*, properties.title, users.name AS tenant_name
                FROM applications
                JOIN properties ON applications.property_id = properties.id
                JOIN users ON applications.tenant_id = users.id
                WHERE properties.owner_id = ?
                ORDER BY applications.id DESC
            """, (owner_id,)).fetchall()
        elif section == "payments":
            records = conn.execute("""
                SELECT payments.*, properties.title, properties.rent AS total_rent,
                       users.name AS tenant_name, verifier.name AS verifier_name
                FROM payments
                LEFT JOIN properties ON payments.property_id = properties.id
                JOIN users ON payments.tenant_id = users.id
                LEFT JOIN users AS verifier ON payments.verified_by = verifier.id
                WHERE properties.owner_id = ?
                ORDER BY payments.id DESC
            """, (owner_id,)).fetchall()
        elif section == "complaints":
            records = conn.execute("""
                SELECT complaints.*, properties.title, users.name AS tenant_name
                FROM complaints
                LEFT JOIN properties ON complaints.property_id = properties.id
                JOIN users ON complaints.tenant_id = users.id
                WHERE properties.owner_id = ?
                ORDER BY complaints.id DESC
            """, (owner_id,)).fetchall()
        elif section == "tenants":
            records = conn.execute("""
                SELECT DISTINCT users.id, users.name, users.email, users.mobile
                FROM leases
                JOIN properties ON leases.property_id = properties.id
                JOIN users ON leases.tenant_id = users.id
                WHERE properties.owner_id = ?
                ORDER BY users.name
            """, (owner_id,)).fetchall()
        elif section == "lease":
            records = conn.execute("""
                SELECT leases.*, properties.title, users.name AS tenant_name
                FROM leases
                JOIN properties ON leases.property_id = properties.id
                JOIN users ON leases.tenant_id = users.id
                WHERE properties.owner_id = ?
                ORDER BY leases.id DESC
            """, (owner_id,)).fetchall()
            lease_properties = conn.execute("SELECT id, title, rent FROM properties WHERE owner_id = ? ORDER BY title", (owner_id,)).fetchall()
            lease_tenants = conn.execute("SELECT id, name, email FROM users WHERE role = 'tenant' ORDER BY name").fetchall()
        elif section == "maintenance":
            records = conn.execute("""
                SELECT maintenance.*, properties.title, users.name AS tenant_name
                FROM maintenance
                LEFT JOIN properties ON maintenance.property_id = properties.id
                LEFT JOIN users ON maintenance.tenant_id = users.id
                WHERE properties.owner_id = ?
                ORDER BY maintenance.id DESC
            """, (owner_id,)).fetchall()
        else:
            records = conn.execute("""
                SELECT
                    (SELECT COUNT(*) FROM properties WHERE owner_id = ?) AS total_properties,
                    (SELECT COALESCE(SUM(rent), 0) FROM properties WHERE owner_id = ?) AS total_rent,
                    (SELECT COUNT(DISTINCT leases.tenant_id) FROM leases JOIN properties ON leases.property_id = properties.id WHERE properties.owner_id = ? AND LOWER(leases.status) = 'active') AS total_tenants,
                    (SELECT COUNT(*) FROM applications JOIN properties ON applications.property_id = properties.id WHERE properties.owner_id = ?) AS total_applications,
                    (SELECT COUNT(*) FROM payments JOIN properties ON payments.property_id = properties.id WHERE properties.owner_id = ?) AS total_payments,
                    (SELECT COALESCE(SUM(payments.amount), 0) FROM payments JOIN properties ON payments.property_id = properties.id WHERE properties.owner_id = ? AND LOWER(payments.status) = 'paid') AS total_paid,
                    (SELECT COUNT(*) FROM complaints JOIN properties ON complaints.property_id = properties.id WHERE properties.owner_id = ?) AS total_complaints,
                    (SELECT COUNT(*) FROM maintenance JOIN properties ON maintenance.property_id = properties.id WHERE properties.owner_id = ?) AS total_maintenance,
                    (SELECT COUNT(*) FROM maintenance JOIN properties ON maintenance.property_id = properties.id WHERE properties.owner_id = ? AND LOWER(maintenance.status) = 'pending') AS pending_maintenance,
                    (SELECT COUNT(*) FROM leases JOIN properties ON leases.property_id = properties.id WHERE properties.owner_id = ?) AS total_leases,
                    (SELECT COUNT(*) FROM leases JOIN properties ON leases.property_id = properties.id WHERE properties.owner_id = ? AND LOWER(leases.status) = 'active') AS active_leases
            """, (owner_id, owner_id, owner_id, owner_id, owner_id, owner_id, owner_id, owner_id, owner_id, owner_id, owner_id)).fetchone()
    finally:
        conn.close()

    return render_template(
        "feature_page.html",
        section=section,
        records=records,
        payment_properties=payment_properties,
        lease_properties=lease_properties,
        lease_tenants=lease_tenants,
        admin_view=False
    )


@app.route("/admin/<section>")
@role_required("admin")
def admin_section(section):
    allowed_sections = ["users", "properties", "applications", "payments", "complaints", "maintenance", "reports"]
    if section not in allowed_sections:
        flash("Page not found!", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    try:
        if section == "users":
            records = conn.execute("SELECT id, name, email, mobile, role FROM users ORDER BY id DESC").fetchall()
        elif section == "properties":
            records = conn.execute("""
                SELECT properties.*, users.name AS owner_name
                FROM properties JOIN users ON properties.owner_id = users.id
                ORDER BY properties.id DESC
            """).fetchall()
        elif section == "applications":
            records = conn.execute("""
                SELECT applications.*, properties.title, users.name AS tenant_name
                FROM applications JOIN properties ON applications.property_id = properties.id
                JOIN users ON applications.tenant_id = users.id ORDER BY applications.id DESC
            """).fetchall()
        elif section == "payments":
            records = conn.execute("""
                SELECT payments.*, properties.title, properties.rent AS total_rent,
                       users.name AS tenant_name, verifier.name AS verifier_name
                FROM payments LEFT JOIN properties ON payments.property_id = properties.id
                JOIN users ON payments.tenant_id = users.id LEFT JOIN users AS verifier ON payments.verified_by = verifier.id
                ORDER BY payments.id DESC
            """).fetchall()
        elif section == "complaints":
            records = conn.execute("""
                SELECT complaints.*, properties.title, users.name AS tenant_name
                FROM complaints LEFT JOIN properties ON complaints.property_id = properties.id
                JOIN users ON complaints.tenant_id = users.id ORDER BY complaints.id DESC
            """).fetchall()
        elif section == "maintenance":
            records = conn.execute("""
                SELECT maintenance.*, properties.title, users.name AS tenant_name
                FROM maintenance LEFT JOIN properties ON maintenance.property_id = properties.id
                LEFT JOIN users ON maintenance.tenant_id = users.id ORDER BY maintenance.id DESC
            """).fetchall()
        else:
            records = conn.execute("""
                SELECT
                    (SELECT COUNT(*) FROM users) AS total_users,
                    (SELECT COUNT(*) FROM users WHERE role = 'owner') AS total_owners,
                    (SELECT COUNT(*) FROM users WHERE role = 'tenant') AS total_tenants,
                    (SELECT COUNT(*) FROM properties) AS total_properties,
                    (SELECT COUNT(*) FROM applications) AS total_applications,
                    (SELECT COUNT(*) FROM payments) AS total_payments,
                    (SELECT COUNT(*) FROM complaints) AS total_complaints,
                    (SELECT COUNT(*) FROM maintenance) AS total_maintenance,
                    (SELECT COALESCE(SUM(amount), 0) FROM payments WHERE LOWER(status) = 'paid') AS total_paid,
                    (SELECT COUNT(*) FROM leases) AS total_leases,
                    (SELECT COUNT(*) FROM leases WHERE LOWER(status) = 'active') AS active_leases,
                    (SELECT COUNT(*) FROM maintenance WHERE LOWER(status) = 'pending') AS pending_maintenance
            """).fetchone()
    finally:
        conn.close()

    return render_template(
        "feature_page.html",
        section=section,
        records=records,
        admin_view=True,
        payment_properties=[],
        lease_properties=[],
        lease_tenants=[]
    )


@app.route("/tenant/<section>")
@role_required("tenant")
def tenant_section(section):
    allowed_sections = ["applications", "payments", "complaints", "lease", "maintenance"]
    if section not in allowed_sections:
        flash("Page not found!", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()
    tenant_id = session["user_id"]
    payment_properties = []

    try:
        # Tenant user active-ஆ உள்ள properties-ஐ எப்போதுமே எடுக்கிறது
        payment_properties = conn.execute("""
            SELECT DISTINCT properties.id, properties.title, leases.rent
            FROM leases
            JOIN properties ON leases.property_id = properties.id
            WHERE leases.tenant_id = ? AND LOWER(leases.status) = 'active'
            ORDER BY properties.title
        """, (tenant_id,)).fetchall()

        if section == "applications":
            records = conn.execute("""
                SELECT applications.*, properties.title
                FROM applications
                JOIN properties ON applications.property_id = properties.id
                WHERE applications.tenant_id = ?
                ORDER BY applications.id DESC
            """, (tenant_id,)).fetchall()
        elif section == "payments":
            records = conn.execute("""
                SELECT payments.*, properties.title, properties.rent AS total_rent,
                       verifier.name AS verifier_name
                FROM payments
                LEFT JOIN properties ON payments.property_id = properties.id
                LEFT JOIN users AS verifier ON payments.verified_by = verifier.id
                WHERE payments.tenant_id = ?
                ORDER BY payments.id DESC
            """, (tenant_id,)).fetchall()
        elif section == "complaints":
            records = conn.execute("""
                SELECT complaints.*, properties.title
                FROM complaints
                LEFT JOIN properties ON complaints.property_id = properties.id
                WHERE complaints.tenant_id = ?
                ORDER BY complaints.id DESC
            """, (tenant_id,)).fetchall()
        elif section == "lease":
            records = conn.execute("""
                SELECT leases.*, properties.title, properties.location
                FROM leases
                JOIN properties ON leases.property_id = properties.id
                WHERE leases.tenant_id = ?
                ORDER BY leases.id DESC
            """, (tenant_id,)).fetchall()
        else:
            records = conn.execute("""
                SELECT maintenance.*, properties.title
                FROM maintenance
                LEFT JOIN properties ON maintenance.property_id = properties.id
                WHERE maintenance.tenant_id = ?
                ORDER BY maintenance.id DESC
            """, (tenant_id,)).fetchall()
    finally:
        conn.close()

    return render_template(
        "feature_page.html",
        section=section,
        records=records,
        payment_properties=payment_properties,
        tenant_properties=payment_properties,
        lease_properties=[],
        lease_tenants=[],
        admin_view=False
    )

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))


@app.route("/")
def home():
    return render_template("index.html")


@app.errorhandler(413)
def file_too_large(error):
    flash("Total upload size maximum 20 MB!", "error")
    return redirect(request.referrer or url_for("profile"))

create_database()
create_admin()

if __name__ == "__main__":
    app.run(
        debug=os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    )