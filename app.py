# আগের সব import ঠিক থাকবে, শুধু render_template যোগ হবে
from flask import Flask, request, jsonify, redirect, render_template # render_template_string এর বদলে render_template

# ... (আপনার আগের সব কোড যেমন আছে থাকবে) ...

# ----------------------
# HTML পেজ দেখানোর জন্য নতুন রুট
# ----------------------

@app.route("/")
def home():
    """হোমপেজ দেখাবে"""
    return render_template("index.html")

@app.route("/login-page")
def login_page():
    """লগইন পেজ দেখাবে"""
    return render_template("login.html")

@app.route("/register-page")
def register_page():
    """রেজিস্টার পেজ দেখাবে"""
    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    """ব্যবহারকারীর ড্যাশবোর্ড দেখাবে"""
    return render_template("dashboard.html")
    
@app.route("/admin-panel")
def admin_page():
    """অ্যাডমিন প্যানেল দেখাবে (এখানেও টোকেন চেক করা উচিত, যা JS দিয়ে করা হবে)"""
    return render_template("admin.html")

# ----------------------
# আপনার আগের API রুটগুলো (কোনো পরিবর্তন ছাড়াই থাকবে)
# ----------------------

@app.route("/register", methods=["POST"])
def register():
    # ... (আগের মতোই)
    # ...

@app.route("/login", methods=["POST"])
def login():
    # ... (আগের মতোই)
    # ...

@app.route("/shorten", methods=["POST"])
@token_required
def shorten(current_user):
    # ... (আগের মতোই)
    # ...

# ... (বাকি সব API রুট আগের মতোই থাকবে) ...

if __name__ == "__main__":
    app.run(debug=True, port=5001)
