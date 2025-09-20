import os
import string
import random
from flask import Flask, request, jsonify, redirect, render_template_string
from pymongo import MongoClient
import jwt
import datetime
from functools import wraps

# ----------------------
# Config
# ----------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "mysecret")

MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://cogana5793:cogana5793@cluster0.1uo0s.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")
client = MongoClient(MONGO_URI)
db = client["shortener"]

# ----------------------
# Helper Functions
# ----------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"error": "Token missing"}), 403
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = db.users.find_one({"username": data["username"]})
        except:
            return jsonify({"error": "Invalid token"}), 403
        return f(current_user, *args, **kwargs)
    return decorated

def generate_short_id():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=6))

# ----------------------
# Routes
# ----------------------

# Home page
@app.route("/")
def home():
    return render_template_string("""
    <h2>🔗 Simple Link Shortener</h2>
    <p>Use API to shorten your links.</p>
    <p><b>Register:</b> POST /register</p>
    <p><b>Login:</b> POST /login</p>
    <p><b>Shorten:</b> POST /shorten (with JWT)</p>
    <p><b>Admin:</b> /admin (username=admin)</p>
    """)

# Register
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    if db.users.find_one({"username": data["username"]}):
        return jsonify({"error": "User exists"})
    db.users.insert_one({"username": data["username"], "password": data["password"], "is_admin": False})
    return jsonify({"message": "User registered!"})

# Login
@app.route("/login", methods=["POST"])
def login():
    data = request.json
    user = db.users.find_one({"username": data["username"], "password": data["password"]})
    if not user:
        return jsonify({"error": "Invalid credentials"})
    token = jwt.encode({"username": user["username"], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config["SECRET_KEY"])
    return jsonify({"token": token})

# Shorten URL
@app.route("/shorten", methods=["POST"])
@token_required
def shorten(current_user):
    data = request.json
    short_id = generate_short_id()
    db.links.insert_one({
        "short_id": short_id,
        "original_url": data["url"],
        "clicks": 0,
        "user": current_user["username"]
    })
    return jsonify({"short_url": request.host_url + short_id})

# Redirect
@app.route("/<short_id>")
def redirect_url(short_id):
    link = db.links.find_one({"short_id": short_id})
    if link:
        db.links.update_one({"short_id": short_id}, {"$inc": {"clicks": 1}})
        return redirect(link["original_url"])
    return jsonify({"error": "Link not found"}), 404

# Stats
@app.route("/stats/<short_id>")
@token_required
def stats(current_user, short_id):
    link = db.links.find_one({"short_id": short_id})
    if not link:
        return jsonify({"error": "Not found"})
    return jsonify({
        "original_url": link["original_url"],
        "short_url": request.host_url + short_id,
        "clicks": link["clicks"]
    })

# Admin Panel
@app.route("/admin")
@token_required
def admin(current_user):
    if not current_user.get("is_admin"):
        return jsonify({"error": "Admins only"})
    users = list(db.users.find({}, {"_id": 0, "password": 0}))
    links = list(db.links.find({}, {"_id": 0}))
    return jsonify({"users": users, "links": links})

# ----------------------
# Run
# ----------------------
if __name__ == "__main__":
    app.run(debug=True)
