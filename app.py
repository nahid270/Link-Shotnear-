# ----------------------
# Imports
# ----------------------
import os
import string
import random
import datetime
from functools import wraps
from flask import Flask, request, jsonify, redirect, render_template_string
from pymongo import MongoClient
import jwt
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------
# App & DB Configuration
# ----------------------
app = Flask(__name__)

# একটি শক্তিশালী এবং গোপন SECRET_KEY ব্যবহার করা আবশ্যক।
# এটি এনভায়রনমেন্ট ভ্যারিয়েবল থেকে লোড করা হচ্ছে।
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "a-very-strong-default-secret-key-for-dev")

# MongoDB কানেকশন। এটিও এনভায়রনমেন্ট ভ্যারিয়েবল থেকে লোড করা হচ্ছে।
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/shortener_db")
try:
    client = MongoClient(MONGO_URI)
    db = client.get_default_database() # URI থেকে ডাটাবেসের নাম নিজে থেকেই নিয়ে নেবে
    # কানেকশন টেস্ট করার জন্য
    client.server_info()
    print("✅ MongoDB connected successfully!")
except Exception as e:
    print(f"❌ Could not connect to MongoDB: {e}")
    # কানেক্ট না হলে অ্যাপ বন্ধ করে দেওয়া ভালো
    exit()

# ----------------------
# Helper Functions
# ----------------------

def token_required(f):
    """JWT Token যাচাই করার জন্য ডেকোরেটর"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Token is missing or invalid"}), 401

        token = auth_header.split(" ")[1]
        try:
            # Token ডিকোড করে payload পাওয়া
            data = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
            # ডাটাবেস থেকে বর্তমান ব্যবহারকারীকে খুঁজে বের করা
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
    """ডাটাবেসে সংঘর্ষ এড়ানোর জন্য একটি ইউনিক শর্ট আইডি তৈরি করে"""
    while True:
        short_id = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
        # আইডিটি আগে থেকেই ডাটাবেসে আছে কিনা তা চেক করা
        if db.links.find_one({"short_id": short_id}) is None:
            return short_id

# ----------------------
# Routes
# ----------------------

@app.route("/")
def home():
    """অ্যাপ্লিকেশনের হোমপেজ, যেখানে API ব্যবহারের তথ্য দেওয়া আছে"""
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Simple Link Shortener</title>
        <style>
            body { font-family: sans-serif; line-height: 1.6; max-width: 600px; margin: 50px auto; padding: 20px; }
            h2 { color: #333; }
            p { color: #555; }
            b { color: #007BFF; }
            code { background-color: #f4f4f4; padding: 2px 5px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h2>🔗 Simple Link Shortener API</h2>
        <p>Use the API endpoints to manage your links.</p>
        <p><b>Register a new user:</b> <code>POST /register</code></p>
        <p><b>Login to get a token:</b> <code>POST /login</code></p>
        <p><b>Shorten a URL:</b> <code>POST /shorten</code> (Requires JWT Authorization: Bearer token)</p>
        <p><b>View link stats:</b> <code>GET /stats/&lt;short_id&gt;</code> (Requires JWT Authorization)</p>
        <p><b>Admin Panel:</b> <code>GET /admin</code> (Requires admin user token)</p>
    </body>
    </html>
    """)

@app.route("/register", methods=["POST"])
def register():
    """নতুন ব্যবহারকারী রেজিস্টার করার জন্য"""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    # ইনপুট ভ্যালিডেশন
    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if db.users.find_one({"username": username}):
        return jsonify({"error": "User with this username already exists"}), 409 # 409 Conflict

    # পাসওয়ার্ড প্লেইন টেক্সটে সেভ না করে হ্যাশ করে সেভ করা হচ্ছে
    hashed_password = generate_password_hash(password)
    db.users.insert_one({
        "username": username,
        "password": hashed_password,
        "is_admin": False # ডিফল্টভাবে কোনো ইউজারই অ্যাডমিন নয়
    })
    return jsonify({"message": f"User '{username}' registered successfully!"}), 201 # 201 Created

@app.route("/login", methods=["POST"])
def login():
    """লগইন করে JWT টোকেন পাওয়ার জন্য"""
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    user = db.users.find_one({"username": username})

    # ব্যবহারকারী আছে কিনা এবং হ্যাশ করা পাসওয়ার্ড মিলছে কিনা তা চেক করা
    if not user or not check_password_hash(user["password"], password):
        return jsonify({"error": "Invalid username or password"}), 401 # 401 Unauthorized

    # টোকেন তৈরি করা, যা ২৪ ঘণ্টা পর্যন্ত ভ্যালিড থাকবে
    token = jwt.encode({
        "username": user["username"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config["SECRET_KEY"], algorithm="HS256")

    return jsonify({"token": token})

@app.route("/shorten", methods=["POST"])
@token_required
def shorten(current_user):
    """একটি নতুন লিঙ্ক শর্ট করার জন্য (টোকেন আবশ্যক)"""
    data = request.get_json()
    original_url = data.get("url")

    if not original_url:
        return jsonify({"error": "URL is required"}), 400

    short_id = generate_unique_short_id()
    db.links.insert_one({
        "short_id": short_id,
        "original_url": original_url,
        "clicks": 0,
        "created_at": datetime.datetime.utcnow(),
        "user": current_user["username"]
    })
    return jsonify({"short_url": f"{request.host_url}{short_id}"}), 201

@app.route("/<short_id>")
def redirect_url(short_id):
    """শর্ট লিঙ্ক থেকে আসল লিঙ্কে রিডাইরেক্ট করার জন্য"""
    # find_one_and_update একটি atomic অপারেশন, যা একসাথে find এবং update করে
    link = db.links.find_one_and_update(
        {"short_id": short_id},
        {"$inc": {"clicks": 1}}
    )
    if link:
        return redirect(link["original_url"])
    else:
        return jsonify({"error": "Link not found"}), 404

@app.route("/stats/<short_id>")
@token_required
def stats(current_user, short_id):
    """লিঙ্কের পরিসংখ্যান দেখার জন্য (টোকেন আবশ্যক)"""
    link = db.links.find_one({"short_id": short_id})

    if not link:
        return jsonify({"error": "Link not found"}), 404

    # শুধুমাত্র লিঙ্কের মালিক অথবা অ্যাডমিন পরিসংখ্যান দেখতে পারবে
    if link["user"] != current_user["username"] and not current_user.get("is_admin"):
        return jsonify({"error": "Access forbidden: you do not own this link"}), 403

    return jsonify({
        "original_url": link["original_url"],
        "short_url": f"{request.host_url}{short_id}",
        "clicks": link["clicks"],
        "created_by": link["user"],
        "created_at": link.get("created_at")
    })

@app.route("/admin")
@token_required
def admin(current_user):
    """অ্যাডমিন প্যানেল (শুধুমাত্র অ্যাডমিনদের জন্য)"""
    if not current_user.get("is_admin"):
        return jsonify({"error": "Forbidden: Admins only"}), 403

    # password ফিল্ড বাদ দিয়ে সব ব্যবহারকারীর তালিকা
    users = list(db.users.find({}, {"_id": 0, "password": 0}))
    # সব লিঙ্কের তালিকা
    links = list(db.links.find({}, {"_id": 0}))
    return jsonify({"users": users, "links": links})

# ----------------------
# Run (for local development)
# ----------------------
if __name__ == "__main__":
    # debug=True প্রোডাকশনে ব্যবহার করা উচিত নয়
    app.run(debug=True, port=5001)
