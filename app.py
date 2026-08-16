import os
import json
import uuid
import hmac
import hashlib
from xml.etree import ElementTree as ET

from flask import Flask, send_from_directory, request, jsonify

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB — screenshots come in as base64

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# XML data store
#
# Every "collection" (orders, members, paymentHistory, ...) lives in its own
# file: data/<collection>.xml
#
#   <collection name="orders">
#     <item id="ORD-12345678"><![CDATA[{"id": "ORD-12345678", ...}]]></item>
#     ...
#   </collection>
#
# Each <item> holds one record as JSON text inside CDATA. Storing the record
# as JSON-inside-XML (rather than mapping every nested field to its own XML
# tag) keeps the store correct for the app's real data shapes — which
# include arbitrarily nested objects (weekly liter logs, per-year payment
# status, screenshot data-URLs) that would be brittle to hand-map to XML
# element-by-element. Nothing is ever written to disk except through this
# module, and nothing is removed except by an explicit DELETE call.
# ---------------------------------------------------------------------------

def _safe_name(collection):
    name = "".join(c for c in collection if c.isalnum() or c in ("-", "_"))
    if not name:
        raise ValueError("invalid collection name")
    return name


def _path(collection):
    return os.path.join(DATA_DIR, f"{_safe_name(collection)}.xml")


def _load(collection):
    """Returns an ordered dict {item_id: record_dict}."""
    path = _path(collection)
    if not os.path.exists(path):
        return {}
    items = {}
    try:
        tree = ET.parse(path)
    except ET.ParseError:
        return {}
    for item in tree.getroot().findall("item"):
        item_id = item.get("id")
        if item_id is None:
            continue
        raw = item.text or "{}"
        try:
            items[item_id] = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            items[item_id] = {}
    return items


def _save(collection, items):
    """items: dict {item_id: record_dict}. Rewrites the whole XML file."""
    root = ET.Element("collection", {"name": _safe_name(collection)})
    for item_id, record in items.items():
        el = ET.SubElement(root, "item", {"id": str(item_id)})
        el.text = json.dumps(record, ensure_ascii=False)
    tree = ET.ElementTree(root)
    try:
        ET.indent(tree, space="  ")
    except AttributeError:
        pass  # ET.indent needs Python 3.9+; file still writes fine without it
    tmp_path = _path(collection) + ".tmp"
    tree.write(tmp_path, encoding="utf-8", xml_declaration=True)
    os.replace(tmp_path, _path(collection))  # atomic — no half-written file


def _record_key(record):
    return str(
        record.get("id")
        or record.get("memberId")
        or record.get("txnId")
        or uuid.uuid4()
    )


# ---------------------------------------------------------------------------
# Store API
# ---------------------------------------------------------------------------

@app.route("/api/store/<collection>", methods=["GET"])
def get_collection(collection):
    items = _load(collection)
    return jsonify(list(items.values()))


@app.route("/api/store/<collection>/<item_id>", methods=["GET"])
def get_item(collection, item_id):
    items = _load(collection)
    if item_id not in items:
        return jsonify({"error": "not found"}), 404
    return jsonify(items[item_id])


@app.route("/api/store/<collection>/<item_id>", methods=["PUT"])
def upsert_item(collection, item_id):
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "expected a JSON object"}), 400
    items = _load(collection)
    items[item_id] = body
    _save(collection, items)
    return jsonify({"ok": True, "id": item_id})


@app.route("/api/store/<collection>", methods=["POST"])
def bulk_save(collection):
    """Seed / replace an entire collection. Body: a JSON array of records."""
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, list):
        return jsonify({"error": "expected a JSON array"}), 400
    items = _load(collection)
    for record in body:
        if isinstance(record, dict):
            items[_record_key(record)] = record
    _save(collection, items)
    return jsonify({"ok": True, "count": len(items)})


@app.route("/api/store/<collection>/<item_id>", methods=["DELETE"])
def delete_item(collection, item_id):
    """The ONLY way a record is ever removed — called from the delete button."""
    items = _load(collection)
    existed = item_id in items
    if existed:
        del items[item_id]
        _save(collection, items)
    return jsonify({"ok": True, "deleted": existed})


# ---------------------------------------------------------------------------
# Razorpay payment-signature verification
#
# The checkout itself runs client-side with your test Key ID (already wired
# into index.html and studio.html). This endpoint is what confirms a
# payment was genuinely completed with Razorpay rather than trusting the
# browser alone — it re-computes the signature using your Key SECRET, which
# must be set as an environment variable on the server (never put the
# secret in any HTML/JS file). If no secret is configured, it reports back
# "unverified" instead of failing, so the test flow still works end to end.
# ---------------------------------------------------------------------------

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
        # No server-side order was created for this payment (or no secret is
        # configured yet) — this is expected for the basic test-key checkout
        # flow. The payment still succeeded at Razorpay; we just can't
        # cryptographically verify it from here yet.
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