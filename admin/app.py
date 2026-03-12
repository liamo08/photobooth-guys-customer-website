import json
import os
import re
import secrets
from functools import wraps
from pathlib import Path

from datetime import datetime, timezone

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from PIL import Image
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent.parent
IMAGES_DIR = BASE_DIR / "images"
ADMIN_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

# Load .env file
if ENV_FILE.exists():
    for line in ENV_FILE.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())
PRODUCTS_FILE = ADMIN_DIR / "products.json"
USERS_FILE = ADMIN_DIR / "users.json"
ENQUIRIES_FILE = ADMIN_DIR / "enquiries.json"

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp", "tiff"}
MAX_IMAGE_WIDTH = 1200
WEBP_QUALITY = 80

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16MB max upload
app.config["APPLICATION_ROOT"] = "/admin"


class PrefixMiddleware:
    """WSGI middleware to handle URL prefix from reverse proxy."""

    def __init__(self, wsgi_app, prefix="/admin"):
        self.app = wsgi_app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path.startswith(self.prefix):
            environ["PATH_INFO"] = path[len(self.prefix):] or "/"
            environ["SCRIPT_NAME"] = self.prefix
        return self.app(environ, start_response)


app.wsgi_app = PrefixMiddleware(app.wsgi_app)


def ensure_users_file():
    if not USERS_FILE.exists():
        default_user = {
            "admin": generate_password_hash("admin")
        }
        USERS_FILE.write_text(json.dumps(default_user, indent=2))


def load_users():
    ensure_users_file()
    return json.loads(USERS_FILE.read_text())


def load_products():
    return json.loads(PRODUCTS_FILE.read_text())


def save_products(products):
    PRODUCTS_FILE.write_text(json.dumps(products, indent=2))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def optimize_image(input_path, output_path, max_width=MAX_IMAGE_WIDTH, quality=WEBP_QUALITY):
    """Convert and optimize an image to WebP format."""
    img = Image.open(input_path)

    if img.mode in ("RGBA", "LA", "P"):
        img = img.convert("RGBA")
    else:
        img = img.convert("RGB")

    w, h = img.size
    if w > max_width:
        ratio = max_width / w
        new_h = int(h * ratio)
        img = img.resize((max_width, new_h), Image.LANCZOS)

    img.save(output_path, "WebP", quality=quality)
    return img.size


def get_image_info(filename):
    """Get file size and dimensions of an image."""
    path = IMAGES_DIR / filename
    if not path.exists():
        return {"exists": False, "size_kb": 0, "width": 0, "height": 0}

    size_kb = path.stat().st_size / 1024
    try:
        img = Image.open(path)
        width, height = img.size
    except Exception:
        width, height = 0, 0

    return {
        "exists": True,
        "size_kb": round(size_kb, 1),
        "width": width,
        "height": height,
    }


def update_html_image_dimensions(product, new_width, new_height):
    """Update width/height attributes in HTML files for a product's image."""
    image_name = product["image"]

    for page in product["pages"]:
        filepath = BASE_DIR / page
        if not filepath.exists():
            continue

        html = filepath.read_text()
        original = html

        def replace_dims(match):
            tag = match.group(0)
            src = re.search(r'src="([^"]*)"', tag)
            if not src:
                return tag
            src_val = src.group(1)
            if not src_val.endswith(image_name):
                return tag

            tag = re.sub(r'width="\d+"', f'width="{new_width}"', tag)
            tag = re.sub(r'height="\d+"', f'height="{new_height}"', tag)
            return tag

        html = re.sub(r"<img[^>]+>", replace_dims, html)

        if html != original:
            filepath.write_text(html)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        users = load_users()

        if username in users and check_password_hash(users[username], password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))

        flash("Invalid username or password", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    products = load_products()
    for product in products:
        product["info"] = get_image_info(product["image"])
    return render_template("dashboard.html", products=products)


@app.route("/upload/<product_id>", methods=["POST"])
@login_required
def upload_image(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)

    if not product:
        flash("Product not found", "error")
        return redirect(url_for("dashboard"))

    if "image" not in request.files:
        flash("No file selected", "error")
        return redirect(url_for("dashboard"))

    file = request.files["image"]
    if file.filename == "":
        flash("No file selected", "error")
        return redirect(url_for("dashboard"))

    if not allowed_file(file.filename):
        flash(f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "error")
        return redirect(url_for("dashboard"))

    tmp_path = IMAGES_DIR / f"_tmp_{secure_filename(file.filename)}"
    output_path = IMAGES_DIR / product["image"]

    try:
        file.save(str(tmp_path))
        new_size = optimize_image(tmp_path, output_path)
        update_html_image_dimensions(product, new_size[0], new_size[1])

        info = get_image_info(product["image"])
        flash(
            f"Image updated for {product['name']} — "
            f"{info['width']}x{info['height']}, {info['size_kb']}KB",
            "success",
        )
    except Exception as e:
        flash(f"Error processing image: {e}", "error")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    return redirect(url_for("dashboard"))


@app.route("/settings")
@login_required
def settings():
    users = load_users()
    usernames = sorted(users.keys())
    return render_template(
        "settings.html",
        usernames=usernames,
        current_user=session.get("username"),
    )


@app.route("/settings/change-password", methods=["POST"])
@login_required
def change_password():
    current = request.form.get("current_password", "")
    new_pw = request.form.get("new_password", "")
    confirm = request.form.get("confirm_password", "")

    if not new_pw or len(new_pw) < 8:
        flash("Password must be at least 8 characters", "error")
        return redirect(url_for("settings"))

    if new_pw != confirm:
        flash("Passwords do not match", "error")
        return redirect(url_for("settings"))

    users = load_users()
    username = session.get("username", "admin")

    if username not in users or not check_password_hash(users[username], current):
        flash("Current password is incorrect", "error")
        return redirect(url_for("settings"))

    users[username] = generate_password_hash(new_pw)
    USERS_FILE.write_text(json.dumps(users, indent=2))
    flash("Password updated successfully", "success")
    return redirect(url_for("settings"))


@app.route("/settings/add-user", methods=["POST"])
@login_required
def add_user():
    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not username or len(username) < 3:
        flash("Username must be at least 3 characters", "error")
        return redirect(url_for("settings"))

    if not re.match(r"^[a-z0-9_.@+-]+$", username):
        flash("Username contains invalid characters", "error")
        return redirect(url_for("settings"))

    if not password or len(password) < 8:
        flash("Password must be at least 8 characters", "error")
        return redirect(url_for("settings"))

    if password != confirm:
        flash("Passwords do not match", "error")
        return redirect(url_for("settings"))

    users = load_users()
    if username in users:
        flash(f"User '{username}' already exists", "error")
        return redirect(url_for("settings"))

    users[username] = generate_password_hash(password)
    USERS_FILE.write_text(json.dumps(users, indent=2))
    flash(f"User '{username}' created successfully", "success")
    return redirect(url_for("settings"))


@app.route("/settings/delete-user", methods=["POST"])
@login_required
def delete_user():
    username = request.form.get("username", "")
    current_user = session.get("username")

    if username == current_user:
        flash("You cannot delete your own account", "error")
        return redirect(url_for("settings"))

    users = load_users()
    if username not in users:
        flash(f"User '{username}' not found", "error")
        return redirect(url_for("settings"))

    if len(users) <= 1:
        flash("Cannot delete the last remaining user", "error")
        return redirect(url_for("settings"))

    del users[username]
    USERS_FILE.write_text(json.dumps(users, indent=2))
    flash(f"User '{username}' deleted", "success")
    return redirect(url_for("settings"))


def load_enquiries():
    if not ENQUIRIES_FILE.exists():
        ENQUIRIES_FILE.write_text("[]")
    return json.loads(ENQUIRIES_FILE.read_text())


def save_enquiry(data):
    enquiries = load_enquiries()
    enquiry = {
        "id": secrets.token_hex(8),
        "name": data.get("name", "").strip(),
        "email": data.get("email", "").strip(),
        "phone": data.get("phone", "").strip(),
        "event_date": data.get("event_date", "").strip(),
        "event_type": data.get("event_type", "").strip(),
        "booth_type": data.get("booth_type", "").strip(),
        "venue": data.get("venue", "").strip(),
        "message": data.get("message", "").strip(),
        "submitted_at": datetime.now(timezone.utc).isoformat(),
        "read": False,
    }
    enquiries.insert(0, enquiry)
    ENQUIRIES_FILE.write_text(json.dumps(enquiries, indent=2))
    return enquiry


@app.route("/enquiry", methods=["POST"])
def receive_enquiry():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Invalid request"}), 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    event_type = data.get("event_type", "").strip()

    if not name or not email or not event_type:
        return jsonify({"success": False, "error": "Name, email, and event type are required"}), 400

    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return jsonify({"success": False, "error": "Invalid email address"}), 400

    save_enquiry(data)
    return jsonify({"success": True})


@app.route("/maps-key")
def maps_key():
    key = os.environ.get("GOOGLE_MAPS_API_KEY", "")
    return jsonify({"key": key})


@app.route("/enquiries")
@login_required
def enquiries():
    all_enquiries = load_enquiries()
    unread = sum(1 for e in all_enquiries if not e.get("read"))
    return render_template("enquiries.html", enquiries=all_enquiries, unread_count=unread)


@app.route("/enquiries/mark-read", methods=["POST"])
@login_required
def mark_enquiry_read():
    enquiry_id = request.form.get("enquiry_id", "")
    all_enquiries = load_enquiries()
    for e in all_enquiries:
        if e["id"] == enquiry_id:
            e["read"] = True
            break
    ENQUIRIES_FILE.write_text(json.dumps(all_enquiries, indent=2))
    return redirect(url_for("enquiries"))


@app.route("/enquiries/delete", methods=["POST"])
@login_required
def delete_enquiry():
    enquiry_id = request.form.get("enquiry_id", "")
    all_enquiries = load_enquiries()
    all_enquiries = [e for e in all_enquiries if e["id"] != enquiry_id]
    ENQUIRIES_FILE.write_text(json.dumps(all_enquiries, indent=2))
    flash("Enquiry deleted", "success")
    return redirect(url_for("enquiries"))


if __name__ == "__main__":
    ensure_users_file()
    app.run(host="127.0.0.1", port=5050, debug=True)
