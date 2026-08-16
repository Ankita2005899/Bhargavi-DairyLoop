import os
import json
import uuid
import hmac
import hashlib

import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool

from flask import Flask, send_from_directory, request, jsonify

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB — screenshots come in as base64

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Postgres data store (replaces the old local-XML-file store)
#
# Render's free filesystem is ephemeral — anything written to disk (like the
# old data/*.xml files) is wiped on every redeploy, restart, or free-tier
# spin-down. A Render PostgreSQL database is persistent, so accounts and
# every other collection now live there instead, and survive indefinitely.
#
# Every "collection" (orders, members, studioAccounts, ...) is just a set of
# rows in one table, keyed by (collection, item_id) — the same shape the app
# already used with the XML store, so nothing in index.html / studio.html
# has to change: they still call GET/PUT/POST/DELETE /api/store/<collection>.
# ---------------------------------------------------------------------------

DATABASE_URL = os.environ.get("DATABASE_URL", "")
# Render (and some other providers) hand out "postgres://..." — psycopg2
# wants "postgresql://...". Normalize so either form works.
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + DATABASE_URL[len("postgres://"):]

_pool = None
if DATABASE_URL:
    _pool = SimpleConnectionPool(1, 10, dsn=DATABASE_URL)


def _get_conn():
    if not _pool:
        raise RuntimeError(
            "DATABASE_URL is not set. Add a Render PostgreSQL database and "
            "link it to this service (Render sets DATABASE_URL for you)."
        )
    return _pool.getconn()


def _put_conn(conn):
    if _pool:
        _pool.putconn(conn)


def init_db():
    if not _pool:
        return
    conn = _get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS store (
                    collection TEXT NOT NULL,
                    item_id    TEXT NOT NULL,
                    data       JSONB NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    PRIMARY KEY (collection, item_id)
                )
            """)
    finally:
        _put_conn(conn)


init_db()


def _record_key(record):
    return str(
        record.get("id")
        or record.get("memberId")
        or record.get("txnId")
        or uuid.uuid4()
    )


# ---------------------------------------------------------------------------
# Store API — same routes and JSON shapes as before
# ---------------------------------------------------------------------------

@app.route("/api/store/<collection>", methods=["GET"])
def get_collection(collection):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT data FROM store WHERE collection = %s ORDER BY updated_at",
                (collection,),
            )
            rows = cur.fetchall()
        return jsonify([row[0] for row in rows])
    finally:
        _put_conn(conn)


@app.route("/api/store/<collection>/<item_id>", methods=["GET"])
def get_item(collection, item_id):
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT data FROM store WHERE collection = %s AND item_id = %s",
                (collection, item_id),
            )
            row = cur.fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(row[0])
    finally:
        _put_conn(conn)


@app.route("/api/store/<collection>/<item_id>", methods=["PUT"])
def upsert_item(collection, item_id):
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "expected a JSON object"}), 400
    conn = _get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO store (collection, item_id, data, updated_at)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (collection, item_id)
                DO UPDATE SET data = EXCLUDED.data, updated_at = now()
                """,
                (collection, item_id, psycopg2.extras.Json(body)),
            )
        return jsonify({"ok": True, "id": item_id})
    finally:
        _put_conn(conn)


@app.route("/api/store/<collection>", methods=["POST"])
def bulk_save(collection):
    """Seed / merge records into a collection. Body: a JSON array of records."""
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, list):
        return jsonify({"error": "expected a JSON array"}), 400
    conn = _get_conn()
    try:
        with conn, conn.cursor() as cur:
            for record in body:
                if isinstance(record, dict):
                    cur.execute(
                        """
                        INSERT INTO store (collection, item_id, data, updated_at)
                        VALUES (%s, %s, %s, now())
                        ON CONFLICT (collection, item_id)
                        DO UPDATE SET data = EXCLUDED.data, updated_at = now()
                        """,
                        (collection, _record_key(record), psycopg2.extras.Json(record)),
                    )
            cur.execute("SELECT COUNT(*) FROM store WHERE collection = %s", (collection,))
            count = cur.fetchone()[0]
        return jsonify({"ok": True, "count": count})
    finally:
        _put_conn(conn)


@app.route("/api/store/<collection>/<item_id>", methods=["DELETE"])
def delete_item(collection, item_id):
    """The ONLY way a record is ever removed — called from the delete button."""
    conn = _get_conn()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM store WHERE collection = %s AND item_id = %s",
                (collection, item_id),
            )
            existed = cur.rowcount > 0
        return jsonify({"ok": True, "deleted": existed})
    finally:
        _put_conn(conn)


# ---------------------------------------------------------------------------
# Razorpay payment-signature verification (unchanged)
# ---------------------------------------------------------------------------

@app.route("/api/config", methods=["GET"])
def public_config():
    return jsonify({
        "razorpayKeyId": os.environ.get("RAZORPAY_KEY_ID", "")
    })


@app.route("/api/razorpay/verify", methods=["POST"])
def razorpay_verify():
    data = request.get_json(force=True, silent=True) or {}
    order_id = data.get("razorpay_order_id")
    payment_id = data.get("razorpay_payment_id")
    signature = data.get("razorpay_signature")
    key_secret = os.environ.get("RAZORPAY_KEY_SECRET", "")

    if not payment_id:
        return jsonify({"verified": False, "reason": "missing payment id"}), 400

    if not (order_id and signature and key_secret):
        return jsonify({"verified": False, "reason": "no order/signature/secret to verify against"})

    payload = f"{order_id}|{payment_id}".encode("utf-8")
    expected = hmac.new(key_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    return jsonify({"verified": hmac.compare_digest(expected, signature)})


# ---------------------------------------------------------------------------
# Static file serving (unchanged)
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return send_from_directory(".", "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(".", filename)


if __name__ == "__main__":
    app.run()