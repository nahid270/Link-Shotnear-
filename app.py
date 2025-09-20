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
# Helper Functions
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
            if not current_user:
                return jsonify({"error": "User not found"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token is invalid"}), 401
        return f(current_user, *args, **kwargs)
    return decorated

def generate_unique_short_id():
    while True:
        short_id = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        if db.links.find_one({"short_id": short_id}) is None:
            return short_id

# ----------------------
# HTML Page Routes (Frontend)
# ----------------------
@app.route("/")
def home_page():
    return render_template("index.html")

@app.route("/login-page")
def login_page():
    return render_template("login.html")

@app.route("/register-page")
def register_page():
    return render_template("register.html")

@app.route("/dashboard")
def dashboard_page():
    return render_template("dashboard.html")

@app.route("/admin-panel") # <-- নতুন অ্যাডমিন প্যানেল রুট
def admin_page():
    return render_template("admin.html")

# Handle favicon requests to prevent errors
@app.route('/favicon.ico')
def favicon():
    return '', 204

# ----------------------
# API Routes (Backend)
# ----------------------
@app.route("/register", methods=["POST"])
def register():
    # ... (এই অংশ এবং বাকি সব API রুট আগের মতোই থাকবে, কোনো পরিবর্তন নেই) ...
    if not db: return jsonify({"error": "Database not connected"}), 500
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    if db.users.find_one({"username": username}):
        return jsonify({"error": "User with this username already exists"}), 409
    hashed_password = generate_password_hash(password)
    db.users.insert_one({"username": username, "password": hashed_password, "is_admin": False})
    return jsonify({"message": f"User '{username}' registered successfully!"}), 201

@app.route("/login", methods=["POST"])
def login():
    if not db: return jsonify({"error": "Database not connected"}), 500
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400
    user = db.users.find_one({"username": username})
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401
    token = jwt.encode({"username": user["username"], "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)}, app.config["SECRET_KEY"], algorithm="HS256")
    return jsonify({"token": token, "username": user['username']})

@app.route("/shorten", methods=["POST"])
@token_required
def shorten(current_user):
    if not db: return jsonify({"error": "Database not connected"}), 500
    data = request.get_json()
    original_url = data.get("url")
    if not original_url:
        return jsonify({"error": "URL is required"}), 400
    short_id = generate_unique_short_id()
    db.links.insert_one({"short_id": short_id, "original_url": original_url, "clicks": 0, "created_at": datetime.datetime.utcnow(), "user": current_user["username"]})
    return jsonify({"short_url": f"{request.host_url}{short_id}"}), 201

@app.route("/user/links")
@token_required
def get_user_links(current_user):
    if not db: return jsonify({"error": "Database not connected"}), 500
    links = list(db.links.find({"user": current_user["username"]}, {"_id": 0}))
    return jsonify(links)

@app.route("/admin") # <-- এটি হলো API রুট, যেখান থেকে অ্যাডমিন ডেটা আসবে
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
    if link:
        return redirect(link["original_url"])
    else:
        return render_template("404.html"), 404

# Main entry point
if __name__ == "__main__":
    app.run(debug=True, port=5001)
