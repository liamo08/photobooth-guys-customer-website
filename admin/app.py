import base64
import hashlib
import json
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import time
import urllib.request
from collections import Counter
from email.mime.text import MIMEText
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
import pillow_heif
pillow_heif.register_heif_opener()
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
SPAM_FILE = ADMIN_DIR / "spam.json"
ANALYTICS_DB = ADMIN_DIR / "analytics.db"

FEATURES_DIR = IMAGES_DIR / "features"
FEATURES_DIR.mkdir(exist_ok=True)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif", "bmp", "tiff", "heic", "heif"}
ALLOWED_VIDEO_EXTENSIONS = {"mp4", "webm", "mov"}
MAX_IMAGE_WIDTH = 1200
WEBP_QUALITY = 80

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB max upload (videos)
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


def allowed_video(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_VIDEO_EXTENSIONS


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
    """Update width/height attributes in ALL HTML files referencing a product's image."""
    image_name = product["image"]

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

    # Scan all HTML files in the project for references to this image
    for filepath in BASE_DIR.rglob("*.html"):
        # Skip admin templates and hidden directories
        rel = filepath.relative_to(BASE_DIR)
        if str(rel).startswith("admin") or str(rel).startswith("."):
            continue

        html = filepath.read_text()
        original = html
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
        CREATE TABLE IF NOT EXISTS page_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            visitor_hash TEXT NOT NULL,
            session_id TEXT NOT NULL,
            page_path TEXT NOT NULL,
            event_type TEXT NOT NULL,
            event_value TEXT DEFAULT '',
            created_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%S','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_pe_session ON page_events(session_id);
        CREATE INDEX IF NOT EXISTS idx_pe_session_type ON page_events(session_id, event_type);
        CREATE INDEX IF NOT EXISTS idx_pe_page ON page_events(page_path);
        CREATE INDEX IF NOT EXISTS idx_pe_created ON page_events(created_at);
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
    if not page_path.startswith("/") or ".." in page_path:
        return "", 204
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    event_type = data.get("t", "pv")
    if event_type not in ("pv", "eng", "click"):
        return "", 204

    conn = get_analytics_db()
    try:
        session_id = resolve_session(conn, visitor_hash, now_str)

        if event_type == "pv":
            referrer = data.get("r", "")[:500]
            try:
                screen_width = int(data.get("w", 0) or 0)
            except (ValueError, TypeError):
                screen_width = 0
            device_type = detect_device(ua, screen_width)
            country, city = lookup_geo(ip)
            conn.execute(
                """INSERT INTO pageviews
                   (visitor_hash, session_id, page_path, referrer, device_type,
                    country, city, screen_width, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (visitor_hash, session_id, page_path, referrer, device_type,
                 country, city, screen_width, now_str),
            )
        elif event_type == "eng":
            try:
                scroll_depth = min(int(data.get("d", 0) or 0), 100)
                time_on_page = min(int(data.get("s", 0) or 0), 3600)
            except (ValueError, TypeError):
                scroll_depth, time_on_page = 0, 0
            conn.execute(
                """INSERT INTO page_events
                   (visitor_hash, session_id, page_path, event_type, event_value, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (visitor_hash, session_id, page_path, "eng",
                 json.dumps({"d": scroll_depth, "s": time_on_page}), now_str),
            )
        elif event_type == "click":
            label = data.get("l", "")[:100]
            conn.execute(
                """INSERT INTO page_events
                   (visitor_hash, session_id, page_path, event_type, event_value, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (visitor_hash, session_id, page_path, "click", label, now_str),
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
                   CAST(SUM(CASE WHEN pv_count = 1 AND has_clicks = 0 THEN 1 ELSE 0 END) AS FLOAT) /
                   NULLIF(COUNT(*), 0) * 100, 0
               ) AS bounce_rate
               FROM (SELECT pv.session_id, COUNT(*) AS pv_count,
                            COALESCE((SELECT COUNT(*) FROM page_events pe
                                      WHERE pe.session_id = pv.session_id
                                      AND pe.event_type = 'click'), 0) AS has_clicks
                     FROM pageviews pv WHERE pv.created_at BETWEEN ? AND ?
                     GROUP BY pv.session_id)""",
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
        active_tab="overview",
    )


def generate_bounce_advice(page_bounces, device_bounces, engagement, cta_clicks, exit_pages):
    advice = []
    clicked_pages = {r["page_path"] for r in cta_clicks}

    for row in page_bounces:
        page = row["entry_page"]
        rate = row["bounce_rate"]
        sessions = row["total_sessions"]
        bounced = row["bounced_sessions"]
        if sessions < 10:
            continue
        has_cta = page in clicked_pages
        if page in ("/", "/index.html") and rate > 60:
            msg = f"Your homepage has a {rate}% bounce rate ({bounced}/{sessions} sessions)."
            if has_cta:
                msg += " CTAs are getting clicks but visitors still leave. Consider stronger above-the-fold content or featured services."
            else:
                msg += " Consider adding a stronger call-to-action above the fold, or feature your most popular services more prominently."
            advice.append({"severity": "high", "page": page, "message": msg})
        elif "/services/" in page and rate > 70:
            msg = f"{page} has a {rate}% bounce rate ({bounced}/{sessions} entry sessions)."
            if has_cta:
                msg += " The page gets CTA clicks from internal visitors but direct-landing visitors leave. Consider improving the page intro for search visitors."
            else:
                msg += " Consider adding pricing info, related services, or a prominent 'Get a Quote' button."
            advice.append({"severity": "high", "page": page, "message": msg})
        elif "/locations/" in page and rate > 65:
            advice.append({"severity": "medium", "page": page,
                "message": f"{page} loses {rate}% of entry visitors ({bounced}/{sessions}). Add local testimonials, a map, or a direct booking link to keep them engaged."})
        elif "/blog/" in page and rate > 80:
            advice.append({"severity": "medium", "page": page,
                "message": f"{page} has a {rate}% bounce rate. Add internal links to your services and a CTA at the end of the post."})
        elif rate > 75:
            advice.append({"severity": "medium", "page": page,
                "message": f"{page} has a {rate}% bounce rate ({bounced}/{sessions} sessions). Review the page content and add clear next steps for visitors."})

    mobile_rate = next((r["bounce_rate"] for r in device_bounces if r["device_type"] == "mobile"), 0)
    desktop_rate = next((r["bounce_rate"] for r in device_bounces if r["device_type"] == "desktop"), 0)
    if mobile_rate > desktop_rate + 15 and mobile_rate > 0:
        advice.append({"severity": "high", "page": "All pages",
            "message": f"Mobile users bounce {round(mobile_rate - desktop_rate, 1)}% more than desktop ({mobile_rate}% vs {desktop_rate}%). Check mobile page speed, button sizes, and overall usability."})

    for row in engagement:
        if row["sample_count"] < 5:
            continue
        if row["avg_scroll_depth"] and row["avg_scroll_depth"] < 40:
            advice.append({"severity": "medium", "page": row["page_path"],
                "message": f"Users only scroll {round(row['avg_scroll_depth'])}% on {row['page_path']}. Move key content and CTAs higher on the page."})
        if row["avg_time_on_page"] and row["avg_time_on_page"] < 10:
            advice.append({"severity": "medium", "page": row["page_path"],
                "message": f"Users spend only {round(row['avg_time_on_page'])}s on {row['page_path']}. The content may not match their search intent."})

    top_entry_pages = {r["entry_page"] for r in page_bounces[:5]}
    for page in top_entry_pages:
        if page not in clicked_pages:
            sessions = next((r["total_sessions"] for r in page_bounces if r["entry_page"] == page), 0)
            if sessions >= 10:
                advice.append({"severity": "high", "page": page,
                    "message": f"{page} receives {sessions} sessions but has zero CTA clicks. Add a prominent call-to-action button."})

    contact_pages = ("/contact.html", "/contact", "/enquiry")
    for row in exit_pages[:5]:
        if row["exit_page"] not in contact_pages and not row["exit_page"].startswith("/admin"):
            advice.append({"severity": "low", "page": row["exit_page"],
                "message": f"Users commonly leave from {row['exit_page']}. Consider adding a 'Get a Quote' link or related content suggestions."})

    severity_order = {"high": 0, "medium": 1, "low": 2}
    advice.sort(key=lambda a: severity_order.get(a["severity"], 3))
    return advice


@app.route("/analytics/bounce")
@login_required
def bounce_analysis():
    end_date = request.args.get("end", datetime.now(timezone.utc).strftime("%Y-%m-%d"))
    start_date = request.args.get(
        "start",
        (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d"),
    )
    start_ts = f"{start_date}T00:00:00"
    end_ts = f"{end_date}T23:59:59"

    conn = get_analytics_db()
    try:
        page_bounces = conn.execute(
            """SELECT entry_page, total_sessions, bounced_sessions,
                      ROUND(CAST(bounced_sessions AS FLOAT) / total_sessions * 100, 1) as bounce_rate
               FROM (
                   SELECT
                       (SELECT page_path FROM pageviews p2
                        WHERE p2.session_id = sub.session_id
                        ORDER BY p2.created_at ASC LIMIT 1) as entry_page,
                       COUNT(*) as total_sessions,
                       SUM(CASE WHEN pv_count = 1 AND has_clicks = 0 THEN 1 ELSE 0 END) as bounced_sessions
                   FROM (
                       SELECT session_id, COUNT(*) as pv_count,
                              COALESCE((SELECT COUNT(*) FROM page_events pe
                                        WHERE pe.session_id = pv.session_id
                                        AND pe.event_type = 'click'), 0) AS has_clicks
                       FROM pageviews pv WHERE pv.created_at BETWEEN ? AND ?
                       GROUP BY session_id
                   ) sub
                   GROUP BY entry_page
               )
               WHERE total_sessions >= 1
               ORDER BY total_sessions DESC LIMIT 20""",
            (start_ts, end_ts),
        ).fetchall()

        exit_pages = conn.execute(
            """SELECT exit_page, COUNT(*) as exit_count
               FROM (
                   SELECT
                       (SELECT page_path FROM pageviews p2
                        WHERE p2.session_id = sub.session_id
                        ORDER BY p2.created_at DESC LIMIT 1) as exit_page
                   FROM (
                       SELECT session_id
                       FROM pageviews WHERE created_at BETWEEN ? AND ?
                       GROUP BY session_id HAVING COUNT(*) > 1
                   ) sub
               )
               GROUP BY exit_page ORDER BY exit_count DESC LIMIT 20""",
            (start_ts, end_ts),
        ).fetchall()

        flow_rows = conn.execute(
            """SELECT session_id, page_path
               FROM pageviews
               WHERE created_at BETWEEN ? AND ?
               AND session_id IN (
                   SELECT session_id FROM pageviews
                   WHERE created_at BETWEEN ? AND ?
                   GROUP BY session_id HAVING COUNT(*) > 1
                   LIMIT 500
               )
               ORDER BY session_id, created_at""",
            (start_ts, end_ts, start_ts, end_ts),
        ).fetchall()

        flow_counter = Counter()
        current_session = None
        current_path = []
        for row in flow_rows:
            if row["session_id"] != current_session:
                if current_path and len(current_path) > 1:
                    path_key = " \u2192 ".join(current_path[:5])
                    flow_counter[path_key] += 1
                current_session = row["session_id"]
                current_path = []
            if not current_path or current_path[-1] != row["page_path"]:
                current_path.append(row["page_path"])
        if current_path and len(current_path) > 1:
            path_key = " \u2192 ".join(current_path[:5])
            flow_counter[path_key] += 1
        user_flows = [{"path": k, "count": v} for k, v in flow_counter.most_common(15)]

        engagement = conn.execute(
            """SELECT page_path,
                      AVG(json_extract(event_value, '$.d')) as avg_scroll_depth,
                      AVG(json_extract(event_value, '$.s')) as avg_time_on_page,
                      COUNT(*) as sample_count
               FROM page_events
               WHERE event_type = 'eng' AND created_at BETWEEN ? AND ?
               GROUP BY page_path
               ORDER BY sample_count DESC""",
            (start_ts, end_ts),
        ).fetchall()

        cta_clicks = conn.execute(
            """SELECT page_path, event_value as cta_label, COUNT(*) as clicks
               FROM page_events
               WHERE event_type = 'click' AND created_at BETWEEN ? AND ?
               GROUP BY page_path, event_value
               ORDER BY clicks DESC LIMIT 30""",
            (start_ts, end_ts),
        ).fetchall()

        device_bounces = conn.execute(
            """SELECT device_type,
                      COUNT(*) as sessions,
                      SUM(CASE WHEN pv_count = 1 AND has_clicks = 0 THEN 1 ELSE 0 END) as bounced,
                      ROUND(CAST(SUM(CASE WHEN pv_count = 1 AND has_clicks = 0 THEN 1 ELSE 0 END) AS FLOAT) /
                            NULLIF(COUNT(*), 0) * 100, 1) as bounce_rate
               FROM (
                   SELECT session_id, COUNT(*) as pv_count,
                          (SELECT device_type FROM pageviews p2
                           WHERE p2.session_id = p1.session_id LIMIT 1) as device_type,
                          COALESCE((SELECT COUNT(*) FROM page_events pe
                                    WHERE pe.session_id = p1.session_id
                                    AND pe.event_type = 'click'), 0) AS has_clicks
                   FROM pageviews p1 WHERE created_at BETWEEN ? AND ?
                   GROUP BY session_id
               )
               GROUP BY device_type ORDER BY sessions DESC""",
            (start_ts, end_ts),
        ).fetchall()

        overall_bounce = conn.execute(
            """SELECT COALESCE(
                   CAST(SUM(CASE WHEN pv_count = 1 AND has_clicks = 0 THEN 1 ELSE 0 END) AS FLOAT) /
                   NULLIF(COUNT(*), 0) * 100, 0
               ) AS bounce_rate, COUNT(*) as total_sessions
               FROM (SELECT pv.session_id, COUNT(*) AS pv_count,
                            COALESCE((SELECT COUNT(*) FROM page_events pe
                                      WHERE pe.session_id = pv.session_id
                                      AND pe.event_type = 'click'), 0) AS has_clicks
                     FROM pageviews pv WHERE pv.created_at BETWEEN ? AND ?
                     GROUP BY pv.session_id)""",
            (start_ts, end_ts),
        ).fetchone()
    finally:
        conn.close()

    advice = generate_bounce_advice(page_bounces, device_bounces, engagement, cta_clicks, exit_pages)

    return render_template(
        "bounce-analysis.html",
        start_date=start_date,
        end_date=end_date,
        page_bounces=page_bounces,
        exit_pages=exit_pages,
        user_flows=user_flows,
        engagement=engagement,
        cta_clicks=cta_clicks,
        device_bounces=device_bounces,
        overall_bounce=round(overall_bounce["bounce_rate"], 1),
        total_sessions=overall_bounce["total_sessions"],
        advice=advice,
        active_tab="bounce",
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


@app.route("/product-settings/<product_id>")
@login_required
def product_settings(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        flash("Product not found", "error")
        return redirect(url_for("dashboard"))
    product["info"] = get_image_info(product["image"])
    for feat in product.get("features", []):
        if feat.get("image"):
            feat["info"] = get_image_info("features/" + feat["image"])
        else:
            feat["info"] = {"exists": False, "size_kb": 0, "width": 0, "height": 0}
        if feat.get("video"):
            vid_path = FEATURES_DIR / feat["video"]
            feat["video_info"] = {
                "exists": vid_path.exists(),
                "size_kb": round(vid_path.stat().st_size / 1024) if vid_path.exists() else 0,
                "filename": feat["video"],
            }
        else:
            feat["video_info"] = {"exists": False, "size_kb": 0, "filename": ""}
    return render_template("product-settings.html", product=product)


@app.route("/product-settings/<product_id>/upload-hero", methods=["POST"])
@login_required
def upload_hero_image(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        flash("Product not found", "error")
        return redirect(url_for("dashboard"))

    if "image" not in request.files or request.files["image"].filename == "":
        flash("No file selected", "error")
        return redirect(url_for("product_settings", product_id=product_id))

    file = request.files["image"]
    if not allowed_file(file.filename):
        flash(f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "error")
        return redirect(url_for("product_settings", product_id=product_id))

    tmp_path = IMAGES_DIR / f"_tmp_{secure_filename(file.filename)}"
    output_path = IMAGES_DIR / product["image"]
    try:
        file.save(str(tmp_path))
        new_size = optimize_image(tmp_path, output_path)
        update_html_image_dimensions(product, new_size[0], new_size[1])
        info = get_image_info(product["image"])
        flash(
            f"Hero image updated — {info['width']}x{info['height']}, {info['size_kb']}KB",
            "success",
        )
    except Exception as e:
        flash(f"Error processing image: {e}", "error")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    return redirect(url_for("product_settings", product_id=product_id))


@app.route("/product-settings/<product_id>/speed", methods=["POST"])
@login_required
def save_carousel_speed(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        flash("Product not found", "error")
        return redirect(url_for("dashboard"))
    try:
        speed = int(request.form.get("speed", 10))
        speed = max(3, min(30, speed))
    except (ValueError, TypeError):
        speed = 10
    product["carousel_speed"] = speed
    save_products(products)
    slide = request.form.get("slide", "0")
    flash(f"Carousel speed set to {speed} seconds", "success")
    return redirect(url_for("product_settings", product_id=product_id, slide=slide))


@app.route("/product-settings/<product_id>/feature", methods=["POST"])
@login_required
def save_feature(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        flash("Product not found", "error")
        return redirect(url_for("dashboard"))

    feature_id = request.form.get("feature_id", "").strip()
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    media_type = request.form.get("media_type", "image").strip()
    slide = request.form.get("slide", "0")

    if media_type not in ("image", "video"):
        media_type = "image"

    if not title or not description:
        flash("Title and description are required", "error")
        return redirect(url_for("product_settings", product_id=product_id, slide=slide))

    if "features" not in product:
        product["features"] = []

    if feature_id:
        feat = next((f for f in product["features"] if f["id"] == feature_id), None)
        if feat:
            feat["title"] = title
            feat["description"] = description
            feat["media_type"] = media_type
            flash(f"Feature '{title}' updated", "success")
        else:
            flash("Feature not found", "error")
    else:
        new_id = secrets.token_hex(6)
        product["features"].append({
            "id": new_id,
            "title": title,
            "description": description,
            "image": "",
            "video": "",
            "media_type": media_type,
        })
        flash(f"Feature '{title}' added", "success")
        slide = str(len(product["features"]) - 1)

    save_products(products)
    return redirect(url_for("product_settings", product_id=product_id, slide=slide))


@app.route("/product-settings/<product_id>/feature/upload", methods=["POST"])
@login_required
def upload_feature_image(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        flash("Product not found", "error")
        return redirect(url_for("dashboard"))

    feature_id = request.form.get("feature_id", "")
    slide = request.form.get("slide", "0")
    feat = next((f for f in product.get("features", []) if f["id"] == feature_id), None)
    if not feat:
        flash("Feature not found", "error")
        return redirect(url_for("product_settings", product_id=product_id))

    if "image" not in request.files or request.files["image"].filename == "":
        flash("No file selected", "error")
        return redirect(url_for("product_settings", product_id=product_id, slide=slide))

    file = request.files["image"]
    app.logger.warning("UPLOAD DEBUG feature: filename=%r, ext=%r", file.filename, file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else "NO_DOT")
    if not allowed_file(file.filename):
        app.logger.warning("UPLOAD DEBUG feature: REJECTED %r", file.filename)
        flash(f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "error")
        return redirect(url_for("product_settings", product_id=product_id, slide=slide))

    filename = f"{product_id}_{feature_id}.webp"
    tmp_path = FEATURES_DIR / f"_tmp_{secure_filename(file.filename)}"
    output_path = FEATURES_DIR / filename

    try:
        file.save(str(tmp_path))
        optimize_image(tmp_path, output_path, max_width=800, quality=85)
        feat["image"] = filename
        save_products(products)
        flash(f"Feature image uploaded for '{feat['title']}'", "success")
    except Exception as e:
        flash(f"Error processing image: {e}", "error")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    return redirect(url_for("product_settings", product_id=product_id, slide=slide))


@app.route("/product-settings/<product_id>/feature/upload-video", methods=["POST"])
@login_required
def upload_feature_video(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        flash("Product not found", "error")
        return redirect(url_for("dashboard"))

    feature_id = request.form.get("feature_id", "")
    slide = request.form.get("slide", "0")
    feat = next((f for f in product.get("features", []) if f["id"] == feature_id), None)
    if not feat:
        flash("Feature not found", "error")
        return redirect(url_for("product_settings", product_id=product_id))

    if "video" not in request.files or request.files["video"].filename == "":
        flash("No video file selected", "error")
        return redirect(url_for("product_settings", product_id=product_id, slide=slide))

    file = request.files["video"]
    if not allowed_video(file.filename):
        flash(f"Invalid video type. Allowed: {', '.join(ALLOWED_VIDEO_EXTENSIONS)}", "error")
        return redirect(url_for("product_settings", product_id=product_id, slide=slide))

    ext = file.filename.rsplit(".", 1)[1].lower()
    filename = f"{product_id}_{feature_id}.{ext}"
    output_path = FEATURES_DIR / filename

    try:
        file.save(str(output_path))
        feat["video"] = filename
        feat["media_type"] = "video"
        save_products(products)
        size_kb = round(output_path.stat().st_size / 1024)
        flash(f"Video uploaded for '{feat['title']}' ({size_kb}KB)", "success")
    except Exception as e:
        flash(f"Error saving video: {e}", "error")

    return redirect(url_for("product_settings", product_id=product_id, slide=slide))


@app.route("/product-settings/<product_id>/feature/delete", methods=["POST"])
@login_required
def delete_feature(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        flash("Product not found", "error")
        return redirect(url_for("dashboard"))

    feature_id = request.form.get("feature_id", "")
    features = product.get("features", [])
    feat = next((f for f in features if f["id"] == feature_id), None)
    if not feat:
        flash("Feature not found", "error")
        return redirect(url_for("product_settings", product_id=product_id))

    if feat.get("image"):
        img_path = FEATURES_DIR / feat["image"]
        if img_path.exists():
            img_path.unlink()
    if feat.get("video"):
        vid_path = FEATURES_DIR / feat["video"]
        if vid_path.exists():
            vid_path.unlink()

    product["features"] = [f for f in features if f["id"] != feature_id]
    save_products(products)
    flash(f"Feature '{feat['title']}' deleted", "success")
    return redirect(url_for("product_settings", product_id=product_id))


@app.route("/product-settings/<product_id>/feature/reorder", methods=["POST"])
@login_required
def reorder_features(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        return jsonify({"success": False, "error": "Product not found"}), 404

    data = request.get_json(silent=True)
    if not data or "order" not in data:
        return jsonify({"success": False, "error": "Invalid request"}), 400

    order = data["order"]
    features = product.get("features", [])
    feat_map = {f["id"]: f for f in features}
    reordered = [feat_map[fid] for fid in order if fid in feat_map]
    product["features"] = reordered
    save_products(products)
    return jsonify({"success": True})


@app.route("/api/features/<product_id>")
def api_features(product_id):
    products = load_products()
    product = next((p for p in products if p["id"] == product_id), None)
    if not product:
        return jsonify({"features": []})
    features = []
    for f in product.get("features", []):
        media_type = f.get("media_type", "image")
        has_media = f.get("image") if media_type == "image" else f.get("video")
        if f.get("title") and has_media:
            feat_data = {
                "id": f["id"],
                "title": f["title"],
                "description": f.get("description", ""),
                "media_type": media_type,
            }
            if media_type == "video" and f.get("video"):
                feat_data["video"] = f"/images/features/{f['video']}"
                if f.get("image"):
                    feat_data["image"] = f"/images/features/{f['image']}"
            else:
                feat_data["image"] = f"/images/features/{f['image']}"
            features.append(feat_data)
    speed = product.get("carousel_speed", 10)
    return jsonify({"features": features, "speed": speed})


# ---------------------------------------------------------------------------
# Page Images management (wedding / corporate page images)
# ---------------------------------------------------------------------------

PAGE_CONFIG_FILE = ADMIN_DIR / "page-config.json"
PAGE_IMAGES_DIR = IMAGES_DIR / "pages"
PAGE_IMAGES_DIR.mkdir(exist_ok=True)


def load_page_config():
    if PAGE_CONFIG_FILE.exists():
        return json.loads(PAGE_CONFIG_FILE.read_text())
    return {}


def save_page_config(config):
    PAGE_CONFIG_FILE.write_text(json.dumps(config, indent=2))


@app.route("/page-images")
@login_required
def page_images():
    config = load_page_config()
    products = load_products()
    product_map = {p["id"]: p["name"] for p in products}
    page_key = request.args.get("page", "wedding-photo-booth-hire.html")
    if page_key not in config:
        page_key = next(iter(config), "")
    page_data = config.get(page_key, {})
    for section in page_data.get("sections", []):
        section["product_name"] = product_map.get(section["product_id"], section["product_id"])
        img = section.get("image", "")
        if img and (PAGE_IMAGES_DIR / img).exists():
            section["info"] = get_image_info("pages/" + img)
        elif img:
            section["info"] = get_image_info(img)
        else:
            section["info"] = {"exists": False, "size_kb": 0, "width": 0, "height": 0}
    hero = page_data.get("hero_image", "")
    if hero and (PAGE_IMAGES_DIR / hero).exists():
        hero_info = get_image_info("pages/" + hero)
    elif hero:
        hero_info = get_image_info(hero)
    else:
        hero_info = {"exists": False, "size_kb": 0, "width": 0, "height": 0}
    return render_template(
        "page-images.html",
        pages=config,
        current_page=page_key,
        page_data=page_data,
        hero_info=hero_info,
        product_map=product_map,
    )


@app.route("/page-images/upload-hero", methods=["POST"])
@login_required
def upload_page_hero():
    config = load_page_config()
    page_key = request.form.get("page_key", "")
    if page_key not in config:
        flash("Page not found", "error")
        return redirect(url_for("page_images"))

    if "image" not in request.files or request.files["image"].filename == "":
        flash("No file selected", "error")
        return redirect(url_for("page_images", page=page_key))

    file = request.files["image"]
    if not allowed_file(file.filename):
        flash(f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "error")
        return redirect(url_for("page_images", page=page_key))

    safe_page = page_key.replace(".html", "").replace("/", "-")
    output_name = f"{safe_page}_hero.webp"
    tmp_path = PAGE_IMAGES_DIR / f"_tmp_{secure_filename(file.filename)}"
    output_path = PAGE_IMAGES_DIR / output_name

    try:
        file.save(str(tmp_path))
        new_size = optimize_image(tmp_path, output_path)
        config[page_key]["hero_image"] = output_name
        save_page_config(config)
        flash(f"Hero image updated — {new_size[0]}x{new_size[1]}", "success")
    except Exception as e:
        flash(f"Error processing image: {e}", "error")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    return redirect(url_for("page_images", page=page_key))


@app.route("/page-images/upload-section", methods=["POST"])
@login_required
def upload_page_section():
    config = load_page_config()
    page_key = request.form.get("page_key", "")
    product_id = request.form.get("product_id", "")

    if page_key not in config:
        flash("Page not found", "error")
        return redirect(url_for("page_images"))

    section = next(
        (s for s in config[page_key].get("sections", []) if s["product_id"] == product_id),
        None,
    )
    if not section:
        flash("Section not found", "error")
        return redirect(url_for("page_images", page=page_key))

    if "image" not in request.files or request.files["image"].filename == "":
        flash("No file selected", "error")
        return redirect(url_for("page_images", page=page_key))

    file = request.files["image"]
    if not allowed_file(file.filename):
        flash(f"Invalid file type. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", "error")
        return redirect(url_for("page_images", page=page_key))

    safe_page = page_key.replace(".html", "").replace("/", "-")
    output_name = f"{safe_page}_{product_id}.webp"
    tmp_path = PAGE_IMAGES_DIR / f"_tmp_{secure_filename(file.filename)}"
    output_path = PAGE_IMAGES_DIR / output_name

    try:
        file.save(str(tmp_path))
        new_size = optimize_image(tmp_path, output_path)
        section["image"] = output_name
        save_page_config(config)
        flash(f"Image updated for {product_id} — {new_size[0]}x{new_size[1]}", "success")
    except Exception as e:
        flash(f"Error processing image: {e}", "error")
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    return redirect(url_for("page_images", page=page_key))


@app.route("/api/page-config/<path:page_name>")
def api_page_config(page_name):
    config = load_page_config()
    page_data = config.get(page_name, {})
    if not page_data:
        return jsonify({})

    hero = page_data.get("hero_image", "")
    hero_path = (
        f"/images/pages/{hero}" if hero and (PAGE_IMAGES_DIR / hero).exists()
        else f"/images/{hero}"
    )

    sections = {}
    for s in page_data.get("sections", []):
        img = s.get("image", "")
        if not img:
            continue
        img_path = (
            f"/images/pages/{img}" if (PAGE_IMAGES_DIR / img).exists()
            else f"/images/{img}"
        )
        sections[s["product_id"]] = {"image": img_path}

    return jsonify({"hero_image": hero_path, "sections": sections})


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


def load_spam():
    if not SPAM_FILE.exists():
        SPAM_FILE.write_text("[]")
    return json.loads(SPAM_FILE.read_text())


def save_spam(data, reason):
    spam_entries = load_spam()
    entry = {
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
        "blocked_reason": reason,
    }
    spam_entries.insert(0, entry)
    # Keep max 100 spam entries to avoid unbounded growth
    spam_entries = spam_entries[:100]
    SPAM_FILE.write_text(json.dumps(spam_entries, indent=2))
    return entry


def send_enquiry_email(enquiry):
    smtp_user = os.environ.get("SMTP_USER", "")
    smtp_pass = os.environ.get("SMTP_PASS", "")
    notify_to = os.environ.get("NOTIFY_EMAIL", "info@photoboothguys.ie")
    if not smtp_user or not smtp_pass:
        logging.warning("SMTP_USER/SMTP_PASS not set, skipping email notification")
        return

    lines = [
        f"New enquiry from {enquiry['name']}",
        "",
        f"Name: {enquiry['name']}",
        f"Email: {enquiry['email']}",
    ]
    if enquiry.get("phone"):
        lines.append(f"Phone: {enquiry['phone']}")
    if enquiry.get("event_date"):
        lines.append(f"Event Date: {enquiry['event_date']}")
    if enquiry.get("event_type"):
        lines.append(f"Event Type: {enquiry['event_type']}")
    if enquiry.get("booth_type"):
        lines.append(f"Booth Type: {enquiry['booth_type']}")
    if enquiry.get("venue"):
        lines.append(f"Venue: {enquiry['venue']}")
    if enquiry.get("message"):
        lines.extend(["", "Message:", enquiry["message"]])

    body = "\n".join(lines)
    msg = MIMEText(body)
    msg["Subject"] = f"New Enquiry: {enquiry['name']} - {enquiry.get('event_type', 'General')}"
    msg["From"] = smtp_user
    msg["To"] = notify_to
    msg["Reply-To"] = enquiry["email"]

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
    except Exception as e:
        logging.error(f"Failed to send enquiry email: {e}")


# --- Spam protection ---
_enquiry_rate_limit = {}  # {ip: [timestamp, ...]}
RATE_LIMIT_MAX = 3
RATE_LIMIT_WINDOW = 3600  # 1 hour

SPAM_KEYWORDS = [
    "keyword placements", "premium keyword", "search terms",
    "guaranteed traffic", "seo", "backlink", "rank your",
    "traffic projections", "secure them before",
    "check availability", "competitors do",
    "marketing campaign", "link building",
]


def _is_spam(data):
    """Check multiple signals. Returns reason string if spam, None if clean."""
    # 1. Honeypot field filled
    if data.get("website", "").strip():
        logging.info("Spam blocked: honeypot field filled")
        return "Honeypot field filled"

    # 2. Time-based check - reject if submitted in under 3 seconds
    token = data.get("form_token", "")
    if token:
        try:
            load_time_ms = int(base64.b64decode(token).decode())
            elapsed_s = (time.time() * 1000 - load_time_ms) / 1000
            if elapsed_s < 3:
                logging.info("Spam blocked: form submitted in %.1fs", elapsed_s)
                return "Submitted too fast (%.1fs)" % elapsed_s
        except (ValueError, Exception):
            logging.info("Spam blocked: invalid form token")
            return "Invalid form token"
    else:
        logging.info("Spam blocked: missing form token")
        return "Missing form token"

    # 3. Event date sanity check - reject dates more than 3 years out
    event_date = data.get("event_date", "").strip()
    if event_date:
        try:
            parsed = datetime.strptime(event_date, "%Y-%m-%d")
            max_date = datetime.now() + timedelta(days=3 * 365)
            if parsed > max_date:
                logging.info("Spam blocked: event date too far in future: %s", event_date)
                return "Event date too far in future (%s)" % event_date
        except ValueError:
            pass

    # 4. Spam keyword detection in message
    message = data.get("message", "").lower()
    matches = sum(1 for kw in SPAM_KEYWORDS if kw in message)
    if matches >= 2:
        logging.info("Spam blocked: %d spam keywords found in message", matches)
        return "Spam keywords detected (%d matches)" % matches

    return None


def _check_rate_limit(ip):
    """Return True if rate limited."""
    now = time.time()
    timestamps = _enquiry_rate_limit.get(ip, [])
    timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
    if len(timestamps) >= RATE_LIMIT_MAX:
        return True
    timestamps.append(now)
    _enquiry_rate_limit[ip] = timestamps
    return False


@app.route("/enquiry", methods=["POST"])
def receive_enquiry():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Invalid request"}), 400

    # Rate limiting
    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    if client_ip:
        client_ip = client_ip.split(",")[0].strip()
    if _check_rate_limit(client_ip):
        logging.info("Spam blocked: rate limit exceeded for %s", client_ip)
        return jsonify({"success": False, "error": "Too many submissions. Please try again later."}), 429

    # Spam detection - save to spam log, silently accept to not tip off bots
    spam_reason = _is_spam(data)
    if spam_reason:
        save_spam(data, spam_reason)
        return jsonify({"success": True})

    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    event_type = data.get("event_type", "").strip()

    if not name or not email or not event_type:
        return jsonify({"success": False, "error": "Name, email, and event type are required"}), 400

    if not re.match(r"^[^@]+@[^@]+\.[^@]+$", email):
        return jsonify({"success": False, "error": "Invalid email address"}), 400

    enquiry = save_enquiry(data)
    send_enquiry_email(enquiry)
    return jsonify({"success": True})


@app.route("/maps-key")
def maps_key():
    key = os.environ.get("GOOGLE_MAPS_API_KEY", "")
    return jsonify({"key": key})


@app.route("/enquiries")
@login_required
def enquiries():
    all_enquiries = load_enquiries()
    spam = load_spam()
    unread = sum(1 for e in all_enquiries if not e.get("read"))
    return render_template("enquiries.html", enquiries=all_enquiries, spam=spam, unread_count=unread, active_tab="enquiries")


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


@app.route("/enquiries/spam")
@login_required
def spam_enquiries():
    spam = load_spam()
    all_enquiries = load_enquiries()
    unread = sum(1 for e in all_enquiries if not e.get("read"))
    return render_template("enquiries.html", enquiries=all_enquiries, spam=spam, unread_count=unread, active_tab="spam")


@app.route("/enquiries/spam/restore", methods=["POST"])
@login_required
def restore_spam():
    spam_id = request.form.get("spam_id", "")
    spam = load_spam()
    entry = None
    remaining = []
    for s in spam:
        if s["id"] == spam_id and entry is None:
            entry = s
        else:
            remaining.append(s)
    if entry:
        SPAM_FILE.write_text(json.dumps(remaining, indent=2))
        enquiry = {
            "id": secrets.token_hex(8),
            "name": entry.get("name", ""),
            "email": entry.get("email", ""),
            "phone": entry.get("phone", ""),
            "event_date": entry.get("event_date", ""),
            "event_type": entry.get("event_type", ""),
            "booth_type": entry.get("booth_type", ""),
            "venue": entry.get("venue", ""),
            "message": entry.get("message", ""),
            "submitted_at": entry.get("submitted_at", datetime.now(timezone.utc).isoformat()),
            "read": False,
        }
        enquiries = load_enquiries()
        enquiries.insert(0, enquiry)
        ENQUIRIES_FILE.write_text(json.dumps(enquiries, indent=2))
        flash("Restored to enquiries", "success")
    return redirect(url_for("spam_enquiries"))


@app.route("/enquiries/spam/delete", methods=["POST"])
@login_required
def delete_spam():
    spam_id = request.form.get("spam_id", "")
    spam = load_spam()
    spam = [s for s in spam if s["id"] != spam_id]
    SPAM_FILE.write_text(json.dumps(spam, indent=2))
    flash("Spam entry deleted", "success")
    return redirect(url_for("spam_enquiries"))


@app.route("/enquiries/spam/clear", methods=["POST"])
@login_required
def clear_spam():
    SPAM_FILE.write_text("[]")
    flash("All spam cleared", "success")
    return redirect(url_for("spam_enquiries"))


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
