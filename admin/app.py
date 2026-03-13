import hashlib
import json
import os
import re
import secrets
import sqlite3
import urllib.request
from functools import wraps
from pathlib import Path

from datetime import datetime, timezone, timedelta

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
ANALYTICS_DB = ADMIN_DIR / "analytics.db"

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


# ---------------------------------------------------------------------------
# Analytics helpers
# ---------------------------------------------------------------------------

def get_analytics_db():
    conn = sqlite3.connect(str(ANALYTICS_DB))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_analytics_db():
    conn = get_analytics_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS pageviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visitor_hash TEXT NOT NULL,
            session_id TEXT NOT NULL,
            page_path TEXT NOT NULL,
            referrer TEXT DEFAULT '',
            device_type TEXT DEFAULT 'desktop',
            country TEXT DEFAULT '',
            city TEXT DEFAULT '',
            screen_width INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_pv_created ON pageviews(created_at);
        CREATE INDEX IF NOT EXISTS idx_pv_visitor ON pageviews(visitor_hash);
        CREATE INDEX IF NOT EXISTS idx_pv_session ON pageviews(session_id);
        CREATE INDEX IF NOT EXISTS idx_pv_page ON pageviews(page_path);
        CREATE TABLE IF NOT EXISTS geo_cache (
            ip_hash TEXT PRIMARY KEY,
            country TEXT DEFAULT '',
            city TEXT DEFAULT '',
            cached_at TEXT
        );
    """)
    conn.close()


def get_real_ip():
    return (
        request.headers.get("CF-Connecting-IP")
        or request.headers.get("X-Real-IP")
        or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.remote_addr
    )


def make_visitor_hash(ip, ua):
    raw = f"{ip}|{ua}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def detect_device(ua, screen_width):
    ua_lower = ua.lower()
    if screen_width > 0:
        if screen_width <= 768:
            return "mobile"
        if screen_width <= 1024:
            return "tablet"
        return "desktop"
    if "mobile" in ua_lower or "android" in ua_lower:
        if "tablet" in ua_lower or "ipad" in ua_lower:
            return "tablet"
        return "mobile"
    if "ipad" in ua_lower or "tablet" in ua_lower:
        return "tablet"
    return "desktop"


def resolve_session(conn, visitor_hash, now_str):
    row = conn.execute(
        """SELECT session_id, created_at FROM pageviews
           WHERE visitor_hash = ?
           ORDER BY created_at DESC LIMIT 1""",
        (visitor_hash,),
    ).fetchone()
    if row:
        last_time = datetime.fromisoformat(row["created_at"])
        now_time = datetime.fromisoformat(now_str)
        if (now_time - last_time) < timedelta(minutes=30):
            return row["session_id"]
    raw = f"{visitor_hash}|{now_str}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def lookup_geo(ip):
    if not ip or ip in ("127.0.0.1", "::1"):
        return ("", "")
    conn = get_analytics_db()
    try:
        ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
        cached = conn.execute(
            "SELECT country, city FROM geo_cache WHERE ip_hash = ?",
            (ip_hash,),
        ).fetchone()
        if cached:
            return (cached["country"], cached["city"])
        try:
            url = f"http://ip-api.com/json/{ip}?fields=country,city,status"
            req = urllib.request.Request(url, headers={"User-Agent": "PhotoboothGuys/1.0"})
            with urllib.request.urlopen(req, timeout=2) as resp:
                data = json.loads(resp.read())
                if data.get("status") == "success":
                    country = data.get("country", "")
                    city = data.get("city", "")
                    conn.execute(
                        "INSERT OR REPLACE INTO geo_cache (ip_hash, country, city, cached_at) VALUES (?, ?, ?, ?)",
                        (ip_hash, country, city, datetime.now(timezone.utc).isoformat()),
                    )
                    conn.commit()
                    return (country, city)
        except Exception:
            pass
        return ("", "")
    finally:
        conn.close()


@app.route("/track", methods=["POST"])
def track_pageview():
    data = request.get_json(silent=True)
    if not data or not data.get("p"):
        return "", 204

    ua = request.headers.get("User-Agent", "")
    ua_lower = ua.lower()
    if any(b in ua_lower for b in ("bot", "crawl", "spider", "lighthouse", "pagespeed")):
        return "", 204

    ip = get_real_ip()
    visitor_hash = make_visitor_hash(ip, ua)
    page_path = data["p"][:500]
    referrer = data.get("r", "")[:500]
    screen_width = int(data.get("w", 0) or 0)
    device_type = detect_device(ua, screen_width)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")

    country, city = lookup_geo(ip)

    conn = get_analytics_db()
    try:
        session_id = resolve_session(conn, visitor_hash, now_str)
        conn.execute(
            """INSERT INTO pageviews
               (visitor_hash, session_id, page_path, referrer, device_type,
                country, city, screen_width, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (visitor_hash, session_id, page_path, referrer, device_type,
             country, city, screen_width, now_str),
        )
        conn.commit()
    finally:
        conn.close()

    return "", 204


@app.route("/analytics")
@login_required
def analytics():
    end_date = request.args.get("end", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    start_date = request.args.get(
        "start",
        (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d"),
    )
    start_ts = f"{start_date}T00:00:00"
    end_ts = f"{end_date}T23:59:59"

    conn = get_analytics_db()
    try:
        overview = conn.execute(
            """SELECT COUNT(*) as total_views,
                      COUNT(DISTINCT visitor_hash) as unique_visitors,
                      COUNT(DISTINCT session_id) as total_sessions
               FROM pageviews WHERE created_at BETWEEN ? AND ?""",
            (start_ts, end_ts),
        ).fetchone()

        bounce = conn.execute(
            """SELECT COALESCE(
                   CAST(SUM(CASE WHEN pv_count = 1 THEN 1 ELSE 0 END) AS FLOAT) /
                   NULLIF(COUNT(*), 0) * 100, 0
               ) AS bounce_rate
               FROM (SELECT session_id, COUNT(*) AS pv_count
                     FROM pageviews WHERE created_at BETWEEN ? AND ?
                     GROUP BY session_id)""",
            (start_ts, end_ts),
        ).fetchone()

        avg_duration = conn.execute(
            """SELECT COALESCE(AVG(duration), 0) as avg_dur FROM (
                   SELECT (julianday(MAX(created_at)) - julianday(MIN(created_at))) * 86400 AS duration
                   FROM pageviews WHERE created_at BETWEEN ? AND ?
                   GROUP BY session_id HAVING COUNT(*) > 1)""",
            (start_ts, end_ts),
        ).fetchone()

        top_pages = conn.execute(
            """SELECT page_path, COUNT(*) as views,
                      COUNT(DISTINCT visitor_hash) as unique_views
               FROM pageviews WHERE created_at BETWEEN ? AND ?
               GROUP BY page_path ORDER BY views DESC LIMIT 20""",
            (start_ts, end_ts),
        ).fetchall()

        devices = conn.execute(
            """SELECT device_type, COUNT(DISTINCT visitor_hash) as count
               FROM pageviews WHERE created_at BETWEEN ? AND ?
               GROUP BY device_type ORDER BY count DESC""",
            (start_ts, end_ts),
        ).fetchall()

        countries = conn.execute(
            """SELECT country, COUNT(DISTINCT visitor_hash) as count
               FROM pageviews WHERE created_at BETWEEN ? AND ?
               AND country != '' GROUP BY country ORDER BY count DESC LIMIT 15""",
            (start_ts, end_ts),
        ).fetchall()

        cities = conn.execute(
            """SELECT city, country, COUNT(DISTINCT visitor_hash) as count
               FROM pageviews WHERE created_at BETWEEN ? AND ?
               AND city != '' GROUP BY city, country ORDER BY count DESC LIMIT 15""",
            (start_ts, end_ts),
        ).fetchall()

        referrers = conn.execute(
            """SELECT referrer, COUNT(*) as count
               FROM pageviews WHERE created_at BETWEEN ? AND ?
               AND referrer != '' GROUP BY referrer ORDER BY count DESC LIMIT 10""",
            (start_ts, end_ts),
        ).fetchall()

        daily = conn.execute(
            """SELECT DATE(created_at) as day, COUNT(*) as views,
                      COUNT(DISTINCT visitor_hash) as visitors
               FROM pageviews WHERE created_at BETWEEN ? AND ?
               GROUP BY day ORDER BY day""",
            (start_ts, end_ts),
        ).fetchall()
    finally:
        conn.close()

    return render_template(
        "analytics.html",
        start_date=start_date,
        end_date=end_date,
        overview=overview,
        bounce_rate=round(bounce["bounce_rate"], 1),
        avg_duration=round(avg_duration["avg_dur"]),
        top_pages=top_pages,
        devices=devices,
        countries=countries,
        cities=cities,
        referrers=referrers,
        daily=daily,
    )


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


@app.route("/image-seo")
@login_required
def image_seo():
    scan_dirs = [
        ("", BASE_DIR),
        ("services/", BASE_DIR / "services"),
        ("locations/", BASE_DIR / "locations"),
    ]
    pages_data = []
    total_images = 0
    images_with_alt = 0
    images_missing_alt = 0

    for prefix, scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        for html_file in sorted(scan_dir.glob("*.html")):
            rel_path = prefix + html_file.name
            html_content = html_file.read_text()
            img_tags = re.findall(r"<img[^>]*>", html_content, re.IGNORECASE)
            if not img_tags:
                continue
            images = []
            for tag in img_tags:
                src_match = re.search(r'src="([^"]*)"', tag)
                alt_match = re.search(r'alt="([^"]*)"', tag)
                src = src_match.group(1) if src_match else ""
                alt = alt_match.group(1) if alt_match else ""
                has_alt = bool(alt_match and alt.strip())
                total_images += 1
                if has_alt:
                    images_with_alt += 1
                else:
                    images_missing_alt += 1
                images.append({
                    "src": src,
                    "alt": alt,
                    "has_alt": has_alt,
                })
            pages_data.append({
                "page": rel_path,
                "images": images,
            })

    return render_template(
        "image-seo.html",
        pages_data=pages_data,
        total_images=total_images,
        images_with_alt=images_with_alt,
        images_missing_alt=images_missing_alt,
    )


@app.route("/image-seo/update", methods=["POST"])
@login_required
def image_seo_update():
    page = request.form.get("page", "")
    src = request.form.get("src", "")
    old_alt = request.form.get("old_alt", "")
    new_alt = request.form.get("new_alt", "")

    if not page or not src:
        flash("Missing required fields", "error")
        return redirect(url_for("image_seo"))

    filepath = BASE_DIR / page
    if not filepath.exists():
        flash(f"File not found: {page}", "error")
        return redirect(url_for("image_seo"))

    html = filepath.read_text()
    original = html

    escaped_src = re.escape(src)
    escaped_old_alt = re.escape(old_alt)
    pattern = re.compile(
        r'(<img\s[^>]*?src="' + escaped_src + r'"[^>]*?)alt="'
        + escaped_old_alt + r'"',
        re.IGNORECASE,
    )
    html = pattern.sub(r'\1alt="' + new_alt.replace("\\", "\\\\") + '"', html, count=1)

    if html == original:
        pattern2 = re.compile(
            r'(<img\s[^>]*?)alt="' + escaped_old_alt
            + r'"([^>]*?src="' + escaped_src + r'")',
            re.IGNORECASE,
        )
        html = pattern2.sub(
            r'\1alt="' + new_alt.replace("\\", "\\\\") + r'"\2', html, count=1
        )

    if html != original:
        filepath.write_text(html)
        flash(f"Alt text updated for {src} on {page}", "success")
    else:
        flash(f"Could not find matching image tag to update", "error")

    return redirect(url_for("image_seo"))


@app.route("/image-seo/bulk-update", methods=["POST"])
@login_required
def image_seo_bulk_update():
    data = request.get_json()
    if not data or "page" not in data or "updates" not in data:
        return jsonify({"success": False, "error": "Invalid request"}), 400

    page = data["page"]
    updates = data["updates"]

    filepath = BASE_DIR / page
    if not filepath.exists():
        return jsonify({"success": False, "error": f"File not found: {page}"}), 404

    html = filepath.read_text()
    original = html
    changed = 0

    for item in updates:
        src = item.get("src", "")
        old_alt = item.get("old_alt", "")
        new_alt = item.get("new_alt", "")
        if not src or old_alt == new_alt:
            continue

        escaped_src = re.escape(src)
        escaped_old_alt = re.escape(old_alt)
        pattern = re.compile(
            r'(<img\s[^>]*?src="' + escaped_src + r'"[^>]*?)alt="'
            + escaped_old_alt + r'"',
            re.IGNORECASE,
        )
        new_html = pattern.sub(
            r'\1alt="' + new_alt.replace("\\", "\\\\") + '"', html, count=1
        )
        if new_html == html:
            pattern2 = re.compile(
                r'(<img\s[^>]*?)alt="' + escaped_old_alt
                + r'"([^>]*?src="' + escaped_src + r'")',
                re.IGNORECASE,
            )
            new_html = pattern2.sub(
                r'\1alt="' + new_alt.replace("\\", "\\\\") + r'"\2',
                html, count=1,
            )
        if new_html != html:
            html = new_html
            changed += 1

    if html != original:
        filepath.write_text(html)

    return jsonify({"success": True, "changed": changed})


ensure_users_file()
init_analytics_db()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5050, debug=True)
