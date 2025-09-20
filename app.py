# ----------------------
# Imports
# ----------------------
import os
import string
import random
import datetime
from functools import wraps
from flask import Flask, request, jsonify, redirect, render_template
from pymongo import MongoClient
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId # <-- নতুন ইম্পোর্ট

# ----------------------
# App & DB Configuration
# ----------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "a-very-strong-default-secret-key-for-dev")
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/shortener_db")

try:
    client = MongoClient(MONGO_URI)
    db = client.get_default_database()
    client.server_info()
    print("✅ MongoDB connected successfully!")
except Exception as e:
    print(f"❌ Could not connect to MongoDB: {e}")
    db = None

# ----------------------
# Helper Functions (আগের মতোই)
# ----------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token is missing or invalid"}), 401
        token = auth_header.split(" ")[1]
        try:
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            current_user = db.users.find_one({"username": data["username"]})
            if not current_user: return jsonify({"error": "User not found"}), 401
        except: return jsonify({"error": "Token is invalid"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def generate_unique_short_id():
    while True:
        short_id = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        if db.links.find_one({"short_id": short_id}) is None:
            return short_id

# ----------------------
# HTML Page Routes (আগের মতোই)
# ----------------------
@app.route("/")
def home_page(): return render_template("index.html")
@app.route("/login-page")
def login_page(): return render_template("login.html")
@app.route("/register-page")
def register_page(): return render_template("register.html")
@app.route("/dashboard")
def dashboard_page(): return render_template("dashboard.html")
@app.route("/admin-panel")
def admin_page(): return render_template("admin.html")
@app.route('/favicon.ico')
def favicon(): return '', 204
@app.route('/favicon.png')
def favicon_png(): return '', 204

# ----------------------
# API Routes (Backend)
# ----------------------
@app.route("/register", methods=["POST"])
def register():
    if not db: return jsonify({"error": "Database not connected"}), 500
    data = request.get_json()
    email = data.get("email") # <-- নতুন: ইমেইল নেওয়া হচ্ছে
    username = data.get("username")
    password = data.get("password")
    if not email or not username or not password:
        return jsonify({"error": "Email, username and password are required"}), 400
    if db.users.find_one({"$or": [{"email": email}, {"username": username}]}):
        return jsonify({"error": "Email or username already exists"}), 409
    
    hashed_password = generate_password_hash(password)
    db.users.insert_one({
        "email": email, # <-- নতুন: ইমেইল সেভ করা হচ্ছে
        "username": username, 
        "password": hashed_password, 
        "is_admin": False
    })
    return jsonify({"message": "User registered successfully!"}), 201

@app.route("/login", methods=["POST"])
def login():
    # ... (এই ফাংশনটি আগের মতোই থাকবে, কোনো পরিবর্তন নেই) ...
    if not db: return jsonify({"error": "Database not connected"}), 500
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password: return jsonify({"error": "Username and password are required"}), 400
    user = db.users.find_one({"username": username})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401
    token = jwt.encode({"username": user["username"], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"token": token, "username": user['username'], "is_admin": user.get('is_admin', False)})

# --- নতুন API: অ্যাডমিন সেটিংস এবং ব্যবহারকারীর আয় গণনার জন্য ---
@app.route("/api/settings", methods=["GET", "POST"])
@token_required
def site_settings(current_user):
    if not db: return jsonify({"error": "Database not connected"}), 500
    
    if request.method == "POST": # অ্যাডমিন সেটিংস সেভ করবে
        if not current_user.get("is_admin"):
            return jsonify({"error": "Forbidden"}), 403
        data = request.get_json()
        cpm_rate = data.get("cpm_rate")
        db.settings.update_one({}, {"$set": {"cpm_rate": float(cpm_rate)}}, upsert=True)
        return jsonify({"message": "Settings updated successfully!"})

    # GET request (সবার জন্য)
    settings = db.settings.find_one()
    if settings:
        return jsonify({"cpm_rate": settings.get("cpm_rate", 0)})
    return jsonify({"cpm_rate": 0}) # ডিফল্ট

# ... (বাকি সব API রুট যেমন shorten, user/links, admin, redirect_url আগের মতোই থাকবে) ...

@app.route("/shorten", methods=["POST"])
@token_required
def shorten(current_user):
    if not db: return jsonify({"error": "Database not connected"}), 500
    data = request.get_json(); original_url = data.get("url")
    if not original_url: return jsonify({"error": "URL is required"}), 400
    short_id = generate_unique_short_id()
    db.links.insert_one({"short_id": short_id, "original_url": original_url, "clicks": 0, "created_at": datetime.datetime.utcnow(), "user": current_user["username"]})
    return jsonify({"short_url": f"{request.host_url}{short_id}"}), 201

@app.route("/user/links")
@token_required
def get_user_links(current_user):
    if not db: return jsonify({"error": "Database not connected"}), 500
    links = list(db.links.find({"user": current_user["username"]}, {"_id": 0}))
    return jsonify(links)

@app.route("/admin")
@token_required
def admin_api(current_user):
    if not current_user.get("is_admin"):
        return jsonify({"error": "Forbidden: Admins only"}), 403
    users = list(db.users.find({}, {"_id": 0, "password": 0}))
    links = list(db.links.find({}, {"_id": 0}))
    return jsonify({"users": users, "links": links})

@app.route("/<short_id>")
def redirect_url(short_id):
    if not db: return jsonify({"error": "Database not connected"}), 500
    link = db.links.find_one_and_update({"short_id": short_id}, {"$inc": {"clicks": 1}})
    if link: return redirect(link["original_url"])
    else: return render_template("404.html"), 404

# Main entry point
if __name__ == "__main__":
    app.run(debug=True, port=5001)
