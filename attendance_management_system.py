from flask import Flask, render_template_string, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os
import datetime
import functools

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "attendtrack-secret-2024-xK9mP")
DATABASE = "attendance.db"

# ─────────────────────────────────────────
# 1. Database Setup
# ─────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()

    # Check if 'users' table exists and what columns it has
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    users_exists = c.fetchone()

    if users_exists:
        c.execute("PRAGMA table_info(users)")
        user_cols = [r[1] for r in c.fetchall()]
        # If old schema used 'email' as the login field, add 'username' alias column
        if 'username' not in user_cols and 'email' in user_cols:
            try:
                c.execute("ALTER TABLE users ADD COLUMN username TEXT")
                c.execute("UPDATE users SET username=email WHERE username IS NULL")
                conn.commit()
            except Exception:
                pass
    else:
        c.execute("""CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'teacher',
            full_name TEXT
        )""")
        conn.commit()

    # Ensure 'approved' and 'created_at' columns don't break anything (old schema compat)
    c.execute("PRAGMA table_info(users)")
    user_cols2 = [r[1] for r in c.fetchall()]
    if 'full_name' not in user_cols2:
        try:
            c.execute("ALTER TABLE users ADD COLUMN full_name TEXT")
            conn.commit()
        except Exception:
            pass

    # Students table
    c.execute("""CREATE TABLE IF NOT EXISTS students (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        roll_no TEXT,
        department TEXT,
        student_username TEXT UNIQUE,
        student_password TEXT
    )""")
    conn.commit()

    # Migration: add student portal columns if missing
    c.execute("PRAGMA table_info(students)")
    stu_cols = [r[1] for r in c.fetchall()]
    if 'student_username' not in stu_cols:
        try:
            c.execute("ALTER TABLE students ADD COLUMN student_username TEXT")
            conn.commit()
        except Exception:
            pass
    if 'student_password' not in stu_cols:
        try:
            c.execute("ALTER TABLE students ADD COLUMN student_password TEXT")
            conn.commit()
        except Exception:
            pass

    # Attendance table
    c.execute("""CREATE TABLE IF NOT EXISTS attendance (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        student_id INTEGER,
        date TEXT,
        status TEXT
    )""")
    conn.commit()

    # Seed default accounts if none exist
    c.execute("SELECT COUNT(*) FROM users WHERE username IS NOT NULL")
    if c.fetchone()[0] == 0:
        for uname, pwd, role, full in [
            ("admin",   "admin123",   "admin",   "Administrator"),
            ("teacher", "teacher123", "teacher", "Class Teacher"),
        ]:
            h = hashlib.sha256(pwd.encode()).hexdigest()
            try:
                c.execute("INSERT INTO users (username,password,role,full_name) VALUES (?,?,?,?)",
                          (uname, h, role, full))
            except Exception:
                pass
        conn.commit()
    conn.close()

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

# ─────────────────────────────────────────
# 2. Auth helpers
# ─────────────────────────────────────────
def login_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session and "student_id" not in session:
            return redirect(url_for("portal"))
        return f(*args, **kwargs)
    return decorated

def staff_required(f):
    """Only admin or teacher can access."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_teacher"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login_admin"))
        if session.get("role") != "admin":
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated

def current_user():
    return {
        "id":        session.get("user_id"),
        "username":  session.get("username", ""),
        "role":      session.get("role", ""),
        "full_name": session.get("full_name", ""),
    }

# ─────────────────────────────────────────
# 3. Portal (role selection landing page)
# ─────────────────────────────────────────
@app.route("/")
def portal():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    if "student_id" in session:
        return redirect(url_for("student_portal"))
    return render_template_string(PORTAL_HTML)

# ─────────────────────────────────────────
# 4. Admin Login
# ─────────────────────────────────────────
@app.route("/login/admin", methods=["GET","POST"])
def login_admin():
    if "user_id" in session and session.get("role") == "admin":
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT id,COALESCE(username,email),password,role,full_name FROM users WHERE (username=? OR email=?) AND role='admin'", (username,username))
        user = c.fetchone()
        conn.close()
        if user and user[2] == hash_pw(password):
            session.clear()
            session["user_id"]   = user[0]
            session["username"]  = user[1]
            session["role"]      = user[3]
            session["full_name"] = user[4]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid admin credentials."
    return render_template_string(LOGIN_ADMIN_HTML, error=error)

# ─────────────────────────────────────────
# 5. Teacher Login
# ─────────────────────────────────────────
@app.route("/login/teacher", methods=["GET","POST"])
def login_teacher():
    if "user_id" in session and session.get("role") == "teacher":
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT id,COALESCE(username,email),password,role,full_name FROM users WHERE (username=? OR email=?) AND role IN ('teacher','admin')", (username,username))
        user = c.fetchone()
        conn.close()
        if user and user[2] == hash_pw(password):
            session.clear()
            session["user_id"]   = user[0]
            session["username"]  = user[1]
            session["role"]      = user[3]
            session["full_name"] = user[4]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid teacher credentials."
    return render_template_string(LOGIN_TEACHER_HTML, error=error)

# ─────────────────────────────────────────
# 6. Student Login
# ─────────────────────────────────────────
@app.route("/login/student", methods=["GET","POST"])
def login_student():
    if "student_id" in session:
        return redirect(url_for("student_portal"))
    error = None
    if request.method == "POST":
        roll_no  = request.form.get("roll_no","").strip()
        password = request.form.get("password","")
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT id,name,roll_no,department,student_password FROM students WHERE roll_no=?", (roll_no,))
        stu = c.fetchone()
        conn.close()
        if stu and stu[4] and stu[4] == hash_pw(password):
            session.clear()
            session["student_id"]   = stu[0]
            session["student_name"] = stu[1]
            session["student_roll"] = stu[2]
            session["student_dept"] = stu[3]
            return redirect(url_for("student_portal"))
        elif stu and not stu[4]:
            error = "No password set for this roll number. Contact your teacher."
        else:
            error = "Invalid Roll No or Password."
    return render_template_string(LOGIN_STUDENT_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("portal"))

# ─────────────────────────────────────────
# 7. Student Portal (view own attendance)
# ─────────────────────────────────────────
@app.route("/student-portal")
def student_portal():
    if "student_id" not in session:
        return redirect(url_for("login_student"))
    sid = session["student_id"]
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id,name,roll_no,department FROM students WHERE id=?", (sid,))
    student = c.fetchone()
    if not student:
        session.clear()
        return redirect(url_for("login_student"))
    c.execute("SELECT date,status FROM attendance WHERE student_id=? ORDER BY date DESC", (sid,))
    raw = c.fetchall()
    conn.close()
    records = []
    for date_str, status in raw:
        try:
            d = datetime.date.fromisoformat(date_str)
            records.append({"date_iso": date_str, "date_fmt": d.strftime("%d %b %Y"),
                            "day": d.strftime("%A"), "status": status})
        except Exception:
            records.append({"date_iso": date_str, "date_fmt": date_str, "day": "", "status": status})
    present = sum(1 for r in records if r["status"] == "Present")
    absent  = len(records) - present
    pct     = round((present / len(records)) * 100, 1) if records else 0
    return render_template_string(STUDENT_PORTAL_HTML,
        student=student, records=records,
        present=present, absent=absent, pct=pct, total=len(records))

# ─────────────────────────────────────────
# 8. Change Password (staff)
# ─────────────────────────────────────────
@app.route("/change-password", methods=["GET","POST"])
@staff_required
def change_password():
    msg = None
    error = None
    if request.method == "POST":
        old = request.form.get("old_password","")
        new = request.form.get("new_password","")
        confirm = request.form.get("confirm_password","")
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE id=?", (session["user_id"],))
        row = c.fetchone()
        if not row or row[0] != hash_pw(old):
            error = "Current password is incorrect."
        elif new != confirm:
            error = "New passwords do not match."
        elif len(new) < 6:
            error = "Password must be at least 6 characters."
        else:
            c.execute("UPDATE users SET password=? WHERE id=?", (hash_pw(new), session["user_id"]))
            conn.commit()
            msg = "Password changed successfully!"
        conn.close()
    return render_template_string(CHANGE_PW_HTML, msg=msg, error=error, user=current_user())

# ─────────────────────────────────────────
# 9. Manage Users (admin only)
# ─────────────────────────────────────────
@app.route("/manage-users", methods=["GET","POST"])
@admin_required
def manage_users():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    msg = None
    error = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            uname = request.form.get("username","").strip()
            pwd   = request.form.get("password","")
            role  = request.form.get("role","teacher")
            full  = request.form.get("full_name","").strip()
            try:
                c.execute("INSERT INTO users (username,password,role,full_name) VALUES (?,?,?,?)",
                          (uname, hash_pw(pwd), role, full))
                conn.commit()
                msg = f"User '{uname}' added."
            except sqlite3.IntegrityError:
                error = f"Username '{uname}' already exists."
        elif action == "delete":
            uid = int(request.form.get("uid",0))
            if uid == session["user_id"]:
                error = "You cannot delete your own account."
            else:
                c.execute("DELETE FROM users WHERE id=?", (uid,))
                conn.commit()
                msg = "User deleted."
    c.execute("SELECT id,username,role,full_name FROM users ORDER BY id")
    users = c.fetchall()
    conn.close()
    return render_template_string(MANAGE_USERS_HTML, users=users, msg=msg, error=error, user=current_user())

# ─────────────────────────────────────────
# 10. Core Routes (staff only)
# ─────────────────────────────────────────
@app.route("/students", methods=["GET","POST"])
@staff_required
def add_student():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    if request.method == "POST":
        name   = request.form.get("name","").strip()
        roll   = request.form.get("roll_no","").strip()
        dept   = request.form.get("department","").strip()
        s_pwd  = request.form.get("student_password","").strip()
        if name:
            hpwd = hash_pw(s_pwd) if s_pwd else None
            try:
                c.execute("INSERT INTO students (name,roll_no,department,student_username,student_password) VALUES (?,?,?,?,?)",
                          (name, roll, dept, roll, hpwd))
                conn.commit()
            except sqlite3.IntegrityError:
                pass
    c.execute("SELECT * FROM students ORDER BY name")
    students = c.fetchall()
    conn.close()
    return render_template_string(ADD_STUDENT_HTML, students=students, user=current_user())

@app.route("/", methods=["GET","POST"])
@staff_required
def add_student_root():
    return redirect(url_for("add_student"))

@app.route("/mark/<int:student_id>", methods=["GET","POST"])
@staff_required
def mark_attendance(student_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id,name FROM students WHERE id=?", (student_id,))
    student = c.fetchone()
    conn.close()
    if request.method == "POST":
        status   = request.form.get("status")
        date_val = request.form.get("date") or datetime.date.today().isoformat()
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO attendance (student_id,date,status) VALUES (?,?,?)",
                  (student_id, date_val, status))
        conn.commit()
        conn.close()
        return redirect(url_for("student_detail", student_id=student_id))
    today_iso = datetime.date.today().isoformat()
    today_fmt = datetime.date.today().strftime("%B %d, %Y")
    return render_template_string(MARK_ATTENDANCE_HTML,
        student_id=student_id, student=student,
        now=today_fmt, today_iso=today_iso, user=current_user())

@app.route("/delete/<int:student_id>", methods=["POST"])
@staff_required
def delete_student(student_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("DELETE FROM attendance WHERE student_id=?", (student_id,))
    c.execute("DELETE FROM students WHERE id=?", (student_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("add_student"))

@app.route("/student/<int:student_id>")
@staff_required
def student_detail(student_id):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id,name,roll_no,department FROM students WHERE id=?", (student_id,))
    student = c.fetchone()
    if not student:
        conn.close()
        return redirect(url_for("add_student"))
    c.execute("SELECT date,status FROM attendance WHERE student_id=? ORDER BY date DESC", (student_id,))
    raw = c.fetchall()
    conn.close()
    records = []
    for date_str, status in raw:
        try:
            d = datetime.date.fromisoformat(date_str)
            records.append({"date_iso": date_str, "date_fmt": d.strftime("%d %b %Y"),
                            "day": d.strftime("%A"), "status": status})
        except Exception:
            records.append({"date_iso": date_str, "date_fmt": date_str, "day": "", "status": status})
    present = sum(1 for r in records if r["status"] == "Present")
    absent  = len(records) - present
    pct     = round((present / len(records)) * 100, 1) if records else 0
    return render_template_string(STUDENT_DETAIL_HTML,
        student=student, records=records,
        present=present, absent=absent, pct=pct,
        total=len(records), user=current_user())

@app.route("/dashboard")
@staff_required
def dashboard():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM students");        total_students = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM attendance WHERE status='Present'"); total_present = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM attendance WHERE status='Absent'");  total_absent  = c.fetchone()[0]
    today = datetime.date.today().isoformat()
    c.execute("SELECT COUNT(*) FROM attendance WHERE date=? AND status='Present'", (today,)); today_present = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM attendance WHERE date=? AND status='Absent'",  (today,)); today_absent  = c.fetchone()[0]
    c.execute("""SELECT students.name,
                        SUM(CASE WHEN attendance.status='Present' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN attendance.status='Absent'  THEN 1 ELSE 0 END)
                 FROM students LEFT JOIN attendance ON students.id=attendance.student_id
                 GROUP BY students.name""")
    student_data = c.fetchall()
    c.execute("""SELECT students.name, attendance.date, attendance.status
                 FROM attendance JOIN students ON students.id=attendance.student_id
                 ORDER BY attendance.id DESC LIMIT 10""")
    recent = c.fetchall()
    conn.close()
    return render_template_string(DASHBOARD_HTML,
        total_students=total_students, total_present=total_present, total_absent=total_absent,
        today_present=today_present, today_absent=today_absent,
        student_data=student_data, recent=recent,
        today_fmt=datetime.date.today().strftime("%B %d, %Y"), user=current_user())

@app.route("/attendance-log")
@staff_required
def attendance_log():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT DISTINCT date FROM attendance ORDER BY date DESC")
    dates = [r[0] for r in c.fetchall()]
    c.execute("SELECT id,name FROM students ORDER BY name")
    students = c.fetchall()
    c.execute("SELECT student_id,date,status FROM attendance")
    lookup = {}
    for sid, d, st in c.fetchall():
        lookup.setdefault(d, {})[sid] = st
    conn.close()
    return render_template_string(ATTENDANCE_LOG_HTML,
        dates=dates, students=students, lookup=lookup, user=current_user())

@app.route("/eligibility-report")
@staff_required
def eligibility_report():
    threshold = int(request.args.get("threshold", 75))
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""SELECT students.id, students.name,
                        COUNT(attendance.id),
                        SUM(CASE WHEN attendance.status='Present' THEN 1 ELSE 0 END)
                 FROM students LEFT JOIN attendance ON students.id=attendance.student_id
                 GROUP BY students.id""")
    rows = c.fetchall()
    conn.close()
    students_data = []
    for sid, name, total, present in rows:
        present = present or 0
        pct = round((present/total*100), 1) if total else 0
        if pct < threshold and (1-threshold/100) > 0:
            needed = (threshold*total/100 - present) / (1 - threshold/100)
            classes_needed = max(0, int(needed) + (1 if needed%1>0 else 0))
        else:
            classes_needed = 0
        risk = "safe" if pct >= threshold else ("warning" if pct >= threshold-15 else "critical")
        students_data.append({"id":sid,"name":name,"total":total,"present":present,
                               "absent":total-present,"pct":pct,"classes_needed":classes_needed,"risk":risk})
    students_data.sort(key=lambda x: ({"critical":0,"warning":1,"safe":2}[x["risk"]], x["pct"]))
    return render_template_string(REPORT_HTML,
        students_data=students_data, threshold=threshold,
        safe_count=sum(1 for s in students_data if s["risk"]=="safe"),
        warning_count=sum(1 for s in students_data if s["risk"]=="warning"),
        critical_count=sum(1 for s in students_data if s["risk"]=="critical"),
        total_count=len(students_data), user=current_user())

# ─────────────────────────────────────────
# 11. Shared Styles
# ─────────────────────────────────────────
BASE_STYLE = """
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;1,9..40,400&family=Syne:wght@700;800&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f0f4f8;--surface:#fff;--surface2:#e8eef5;
  --ink:#1a2332;--ink-muted:#637083;
  --accent:#2563eb;--accent-light:#dbeafe;
  --success:#059669;--success-light:#d1fae5;
  --danger:#dc2626;--danger-light:#fee2e2;
  --warning:#d97706;--warning-light:#fef3c7;
  --admin-color:#7c3aed;--admin-light:#ede9fe;
  --teacher-color:#0891b2;--teacher-light:#cffafe;
  --student-color:#059669;--student-light:#d1fae5;
  --radius:14px;
  --shadow:0 2px 12px rgba(0,0,0,.07),0 1px 3px rgba(0,0,0,.05);
  --shadow-lg:0 8px 32px rgba(0,0,0,.10),0 2px 8px rgba(0,0,0,.06);
}
body{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--ink);min-height:100vh}
.page-wrapper{max-width:900px;margin:0 auto;padding:36px 24px 80px}

/* ── Header ── */
.site-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:36px;padding-bottom:20px;border-bottom:1px solid var(--surface2)}
.logo{display:flex;align-items:center;gap:12px;text-decoration:none}
.logo-icon{width:40px;height:40px;background:var(--accent);border-radius:10px;display:flex;align-items:center;justify-content:center}
.logo-icon svg{width:20px;height:20px;fill:white}
.logo-text{font-family:'Syne',sans-serif;font-size:18px;font-weight:800;color:var(--ink);letter-spacing:-.5px}
.logo-text span{color:var(--accent)}
.header-right{display:flex;align-items:center;gap:8px}
.nav-links{display:flex;gap:6px;align-items:center}
.nav-btn{font-family:'DM Sans',sans-serif;font-size:13px;font-weight:500;padding:7px 14px;border-radius:8px;border:1px solid transparent;cursor:pointer;text-decoration:none;transition:all .18s;color:var(--ink-muted);background:transparent;white-space:nowrap}
.nav-btn:hover{background:var(--surface2);color:var(--ink)}
.nav-btn.active{background:var(--accent-light);color:var(--accent);border-color:#bfdbfe}
.user-pill{display:flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--surface2);border-radius:99px;padding:5px 14px 5px 6px;font-size:13px;font-weight:500;color:var(--ink);text-decoration:none;transition:all .18s}
.user-pill:hover{border-color:#bfdbfe;background:var(--accent-light)}
.user-avatar-sm{width:26px;height:26px;border-radius:50%;background:var(--accent);color:#fff;font-size:11px;font-weight:800;display:flex;align-items:center;justify-content:center}
.admin-badge{font-size:10px;font-weight:700;padding:1px 6px;border-radius:99px;background:#fef3c7;color:#92400e;margin-left:2px}
.logout-btn{font-size:12px;font-weight:600;padding:6px 12px;border-radius:8px;border:1px solid var(--surface2);background:var(--surface);color:var(--ink-muted);cursor:pointer;text-decoration:none;transition:all .18s}
.logout-btn:hover{background:var(--danger-light);color:var(--danger);border-color:#fca5a5}

/* ── Cards ── */
.card{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);padding:26px 30px;margin-bottom:20px;animation:slideUp .3s ease both}
.card-title{font-family:'Syne',sans-serif;font-size:18px;font-weight:700;color:var(--ink);margin-bottom:18px;letter-spacing:-.4px}

/* ── Forms ── */
.form-group{margin-bottom:16px}
.form-label{display:block;font-size:12px;font-weight:600;color:var(--ink-muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:7px}
.form-input{width:100%;font-family:'DM Sans',sans-serif;font-size:14.5px;padding:10px 15px;border:1.5px solid var(--surface2);border-radius:10px;outline:none;color:var(--ink);background:var(--bg);transition:border-color .18s}
.form-input:focus{border-color:var(--accent);background:#fff}
.form-row{display:flex;gap:10px;align-items:flex-end}
.form-row .form-group{flex:1}

/* ── Buttons ── */
.btn{font-family:'DM Sans',sans-serif;font-size:14px;font-weight:600;padding:10px 20px;border:none;border-radius:10px;cursor:pointer;transition:all .18s;text-decoration:none;display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#1d4ed8;transform:translateY(-1px);box-shadow:0 4px 14px rgba(37,99,235,.3)}
.btn-success{background:var(--success);color:#fff}
.btn-success:hover{background:#047857;transform:translateY(-1px)}
.btn-danger{background:var(--danger);color:#fff}
.btn-danger:hover{background:#b91c1c;transform:translateY(-1px)}
.btn-ghost{background:var(--surface2);color:var(--ink)}
.btn-ghost:hover{background:#d1dae5}
.btn-sm{padding:7px 14px;font-size:12px}

/* ── Student List ── */
.student-list{list-style:none;display:flex;flex-direction:column;gap:9px}
.student-item{display:flex;align-items:center;justify-content:space-between;padding:13px 16px;background:var(--bg);border-radius:10px;border:1px solid var(--surface2);transition:all .18s;animation:slideUp .3s ease both}
.student-item:hover{background:var(--accent-light);border-color:#bfdbfe;transform:translateX(3px)}
.student-info{display:flex;align-items:center;gap:11px}
.student-avatar{width:36px;height:36px;background:var(--accent-light);border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;color:var(--accent);flex-shrink:0}
.student-name{font-weight:500;font-size:14.5px}
.student-meta{font-size:12px;color:var(--ink-muted);margin-top:1px}

/* ── Stats ── */
.stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:20px}
.stat-card{background:var(--surface);border-radius:var(--radius);padding:18px 20px;box-shadow:var(--shadow);text-align:center}
.stat-value{font-family:'Syne',sans-serif;font-size:28px;font-weight:800;color:var(--ink);line-height:1;margin-bottom:5px}
.stat-label{font-size:11px;font-weight:500;color:var(--ink-muted);text-transform:uppercase;letter-spacing:.06em}
.stat-card.accent .stat-value{color:var(--accent)}
.stat-card.success .stat-value{color:var(--success)}
.stat-card.danger .stat-value{color:var(--danger)}

/* ── Page Hero ── */
.page-hero{margin-bottom:28px}
.page-hero h1{font-family:'Syne',sans-serif;font-size:26px;font-weight:800;letter-spacing:-.7px;margin-bottom:5px}
.page-hero p{font-size:14.5px;color:var(--ink-muted)}

/* ── Mark Attendance ── */
.attendance-options{display:flex;gap:14px;margin:4px 0 20px}
.attendance-radio{display:none}
.attendance-label{flex:1;display:flex;flex-direction:column;align-items:center;gap:10px;padding:20px 16px;border-radius:12px;border:2px solid var(--surface2);cursor:pointer;transition:all .2s;font-weight:600;font-size:14px;color:var(--ink-muted)}
.attendance-label svg{width:26px;height:26px}
.attendance-label:hover{border-color:#93c5fd;background:var(--accent-light);color:var(--accent)}
.attendance-radio:checked + .attendance-label{border-color:var(--accent);background:var(--accent-light);color:var(--accent);box-shadow:0 0 0 3px rgba(37,99,235,.1)}
.attendance-radio#absent:checked + .attendance-label{border-color:var(--danger);background:var(--danger-light);color:var(--danger);box-shadow:0 0 0 3px rgba(220,38,38,.1)}

/* ── Empty ── */
.empty-state{text-align:center;padding:40px 20px;color:var(--ink-muted);font-size:14px}
.empty-state svg{width:38px;height:38px;margin-bottom:12px;opacity:.35}

/* ── Flash ── */
.flash{padding:12px 18px;border-radius:10px;font-size:14px;font-weight:500;margin-bottom:18px;animation:slideUp .25s ease both}
.flash.success{background:var(--success-light);color:var(--success);border:1px solid #a7f3d0}
.flash.error{background:var(--danger-light);color:var(--danger);border:1px solid #fca5a5}

/* ── Tables ── */
.data-table{width:100%;border-collapse:collapse}
.data-table th{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--ink-muted);padding:10px 14px;text-align:left;border-bottom:1.5px solid var(--surface2)}
.data-table td{padding:13px 14px;font-size:14px;border-bottom:1px solid var(--surface2);vertical-align:middle}
.data-table tr:last-child td{border-bottom:none}
.data-table tr:hover td{background:#f7f9fc}

/* ── Profile ── */
.profile-card{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);padding:24px 28px;margin-bottom:20px;display:flex;align-items:center;gap:20px;animation:slideUp .25s ease both}
.profile-avatar{width:60px;height:60px;border-radius:50%;background:var(--accent-light);color:var(--accent);display:flex;align-items:center;justify-content:center;font-family:'Syne',sans-serif;font-size:24px;font-weight:800;flex-shrink:0}
.profile-info{flex:1}
.profile-name{font-family:'Syne',sans-serif;font-size:20px;font-weight:800;letter-spacing:-.4px;margin-bottom:3px}
.profile-meta{font-size:13px;color:var(--ink-muted)}
.profile-stats{display:flex;gap:20px;margin-left:auto;flex-shrink:0}
.p-stat{text-align:center}
.p-stat-val{font-family:'Syne',sans-serif;font-size:20px;font-weight:800;line-height:1}
.p-stat-lbl{font-size:10px;color:var(--ink-muted);font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-top:2px}

/* ── History ── */
.history-card{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden;animation:slideUp .3s ease both}
.history-header{padding:18px 24px 14px;border-bottom:1px solid var(--surface2);display:flex;align-items:center;justify-content:space-between}
.history-title{font-family:'Syne',sans-serif;font-size:16px;font-weight:700}
.filter-btns{display:flex;gap:5px}
.filter-btn{font-size:11.5px;font-weight:600;padding:5px 13px;border-radius:99px;border:1.5px solid var(--surface2);background:transparent;color:var(--ink-muted);cursor:pointer;transition:all .15s}
.filter-btn:hover{background:var(--surface2);color:var(--ink)}
.filter-btn.active-all{background:var(--accent-light);border-color:#bfdbfe;color:var(--accent)}
.filter-btn.active-present{background:var(--success-light);border-color:#a7f3d0;color:var(--success)}
.filter-btn.active-absent{background:var(--danger-light);border-color:#fca5a5;color:var(--danger)}
.record-row{display:flex;align-items:center;justify-content:space-between;padding:12px 24px;border-bottom:1px solid var(--surface2);transition:background .15s;animation:slideUp .25s ease both}
.record-row:last-child{border-bottom:none}
.record-row:hover{background:#f7f9fc}
.record-date{display:flex;align-items:center;gap:12px}
.date-icon{width:36px;height:36px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;font-size:12px;font-weight:700}
.date-icon.present{background:var(--success-light);color:var(--success)}
.date-icon.absent{background:var(--danger-light);color:var(--danger)}
.date-text{font-size:14px;font-weight:500}
.date-day{font-size:11px;color:var(--ink-muted);margin-top:1px}
.status-tag{font-size:11.5px;font-weight:700;padding:3px 11px;border-radius:99px}
.status-tag.present{background:var(--success-light);color:var(--success)}
.status-tag.absent{background:var(--danger-light);color:var(--danger)}

/* ── Progress ── */
.progress-bar-wrap{display:flex;align-items:center;gap:10px}
.progress-bar-bg{flex:1;height:6px;background:var(--surface2);border-radius:99px;overflow:hidden;min-width:70px}
.progress-bar-fill{height:100%;border-radius:99px;transition:width .6s cubic-bezier(.4,0,.2,1)}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:11.5px;font-weight:600}
.badge-high{background:var(--success-light);color:var(--success)}
.badge-mid{background:var(--warning-light);color:var(--warning)}
.badge-low{background:var(--danger-light);color:var(--danger)}

/* ── Attendance Log Table ── */
.log-table-wrap{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);overflow-x:auto}
.log-table{width:100%;border-collapse:collapse;min-width:500px}
.log-table th{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--ink-muted);padding:10px 13px;text-align:left;background:var(--bg);border-bottom:1.5px solid var(--surface2)}
.log-table td{padding:11px 13px;border-bottom:1px solid var(--surface2);font-size:13.5px;vertical-align:middle}
.log-table tr:last-child td{border-bottom:none}
.log-table tr:hover td{background:#f7f9fc}
.dot-present{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;background:var(--success-light);border-radius:50%;font-size:12px;color:var(--success);font-weight:700}
.dot-absent{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;background:var(--danger-light);border-radius:50%;font-size:12px;color:var(--danger);font-weight:700}
.dot-none{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;background:var(--surface2);border-radius:50%;font-size:11px;color:var(--ink-muted)}
.pct-pill{font-size:11px;font-weight:700;padding:2px 8px;border-radius:99px}
.pct-high{background:var(--success-light);color:var(--success)}
.pct-mid{background:var(--warning-light);color:var(--warning)}
.pct-low{background:var(--danger-light);color:var(--danger)}

/* ── Eligibility Report ── */
.threshold-bar{display:flex;align-items:center;gap:14px;background:var(--surface);border-radius:var(--radius);padding:16px 22px;margin-bottom:20px;box-shadow:var(--shadow)}
.threshold-slider{flex:1;-webkit-appearance:none;height:6px;border-radius:99px;background:linear-gradient(to right,var(--accent) 0%,var(--accent) var(--val),var(--surface2) var(--val),var(--surface2) 100%);outline:none;cursor:pointer}
.threshold-slider::-webkit-slider-thumb{-webkit-appearance:none;width:18px;height:18px;border-radius:50%;background:var(--accent);border:3px solid #fff;box-shadow:0 1px 6px rgba(37,99,235,.4);cursor:pointer}
.threshold-val{font-family:'Syne',sans-serif;font-size:19px;font-weight:800;color:var(--accent);min-width:46px;text-align:right}
.risk-summary{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px}
.risk-stat{background:var(--surface);border-radius:var(--radius);padding:16px 18px;text-align:center;box-shadow:var(--shadow);border-top:3px solid transparent}
.risk-stat.all{border-color:var(--accent)} .risk-stat.safe{border-color:var(--success)}
.risk-stat.warning{border-color:var(--warning)} .risk-stat.critical{border-color:var(--danger)}
.risk-stat-num{font-family:'Syne',sans-serif;font-size:24px;font-weight:800;line-height:1;margin-bottom:3px}
.risk-stat.all .risk-stat-num{color:var(--accent)} .risk-stat.safe .risk-stat-num{color:var(--success)}
.risk-stat.warning .risk-stat-num{color:var(--warning)} .risk-stat.critical .risk-stat-num{color:var(--danger)}
.risk-stat-lbl{font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--ink-muted)}
.defaulter-row{display:flex;align-items:center;gap:14px;padding:14px 18px;background:var(--surface);border-radius:12px;margin-bottom:8px;box-shadow:var(--shadow);border-left:4px solid transparent;transition:transform .15s,box-shadow .15s;animation:slideUp .3s ease both}
.defaulter-row:hover{transform:translateX(3px);box-shadow:var(--shadow-lg)}
.defaulter-row.safe{border-color:var(--success)} .defaulter-row.warning{border-color:var(--warning)} .defaulter-row.critical{border-color:var(--danger)}
.def-avatar{width:38px;height:38px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:14px;flex-shrink:0}
.safe .def-avatar{background:var(--success-light);color:var(--success)}
.warning .def-avatar{background:var(--warning-light);color:var(--warning)}
.critical .def-avatar{background:var(--danger-light);color:var(--danger)}
.def-main{flex:1;min-width:0}
.def-name{font-weight:600;font-size:14px;margin-bottom:5px}
.def-bar-wrap{display:flex;align-items:center;gap:9px}
.def-bar-bg{flex:1;height:5px;background:var(--surface2);border-radius:99px;overflow:hidden}
.def-bar-fill{height:100%;border-radius:99px}
.safe .def-bar-fill{background:var(--success)} .warning .def-bar-fill{background:var(--warning)} .critical .def-bar-fill{background:var(--danger)}
.def-pct{font-size:12px;font-weight:700;min-width:36px;text-align:right}
.safe .def-pct{color:var(--success)} .warning .def-pct{color:var(--warning)} .critical .def-pct{color:var(--danger)}
.def-stats{display:flex;flex-direction:column;align-items:flex-end;gap:4px;flex-shrink:0}
.def-counts{font-size:11.5px;color:var(--ink-muted)}
.def-counts span{font-weight:600;color:var(--ink)}
.need-badge{font-size:11px;font-weight:700;padding:2px 9px;border-radius:99px;white-space:nowrap}
.safe .need-badge{background:var(--success-light);color:var(--success)}
.warning .need-badge{background:var(--warning-light);color:var(--warning)}
.critical .need-badge{background:var(--danger-light);color:var(--danger)}
.section-heading{font-family:'Syne',sans-serif;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--ink-muted);margin:20px 0 9px;display:flex;align-items:center;gap:8px}
.section-heading::after{content:'';flex:1;height:1px;background:var(--surface2)}
.dot-c{width:7px;height:7px;border-radius:50%;background:var(--danger);display:inline-block}
.dot-w{width:7px;height:7px;border-radius:50%;background:var(--warning);display:inline-block}
.dot-s{width:7px;height:7px;border-radius:50%;background:var(--success);display:inline-block}

/* ── Dashboard ── */
.dashboard-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:20px}
.chart-card{background:var(--surface);border-radius:var(--radius);box-shadow:var(--shadow);padding:22px 26px;animation:slideUp .35s ease both}
.chart-card.full{grid-column:1/-1}
.chart-title{font-family:'Syne',sans-serif;font-size:15px;font-weight:700;margin-bottom:16px;letter-spacing:-.3px}
.pie-wrap{display:flex;align-items:center;gap:24px}
.pie-canvas-wrap{position:relative;width:170px;height:170px;flex-shrink:0}
.pie-center-label{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);text-align:center;pointer-events:none}
.pie-center-num{font-family:'Syne',sans-serif;font-size:24px;font-weight:800;color:var(--ink);line-height:1}
.pie-center-sub{font-size:10px;color:var(--ink-muted);font-weight:500}
.pie-legend{flex:1;display:flex;flex-direction:column;gap:10px}
.legend-item{display:flex;align-items:center;gap:9px}
.legend-dot{width:11px;height:11px;border-radius:50%;flex-shrink:0}
.legend-label{font-size:12px;font-weight:500;color:var(--ink-muted)}
.legend-val{font-size:18px;font-weight:700;font-family:'Syne',sans-serif}
.today-badge{display:inline-flex;align-items:center;gap:6px;background:var(--accent-light);color:var(--accent);font-size:11.5px;font-weight:600;padding:4px 11px;border-radius:99px;margin-bottom:16px}
.today-row{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.today-stat{border-radius:11px;padding:16px 18px;display:flex;align-items:center;gap:12px}
.today-stat.present-card{background:var(--success-light)} .today-stat.absent-card{background:var(--danger-light)}
.today-stat-icon{width:40px;height:40px;border-radius:9px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.today-stat.present-card .today-stat-icon{background:var(--success)} .today-stat.absent-card .today-stat-icon{background:var(--danger)}
.today-stat-icon svg{width:18px;height:18px;fill:white}
.today-stat-num{font-family:'Syne',sans-serif;font-size:24px;font-weight:800;line-height:1}
.today-stat.present-card .today-stat-num{color:var(--success)} .today-stat.absent-card .today-stat-num{color:var(--danger)}
.today-stat-lbl{font-size:11px;font-weight:500;color:var(--ink-muted);margin-top:2px}
.activity-list{list-style:none;display:flex;flex-direction:column;gap:0}
.activity-item{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--surface2);font-size:13.5px}
.activity-item:last-child{border-bottom:none}
.activity-name{font-weight:500}
.activity-date{font-size:11.5px;color:var(--ink-muted);margin-top:1px}
.status-pill{font-size:11.5px;font-weight:700;padding:3px 10px;border-radius:99px}
.status-pill.present{background:var(--success-light);color:var(--success)}
.status-pill.absent{background:var(--danger-light);color:var(--danger)}

@keyframes slideUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.page-wrapper>*{animation:slideUp .3s ease both}
"""

# ─────────────────────────────────────────
# 12. Shared Nav macro
# ─────────────────────────────────────────
NAV_MACRO = """
{% macro navbar(active='') %}
<header class="site-header">
  <a href="/dashboard" class="logo">
    <div class="logo-icon"><svg viewBox="0 0 24 24"><path d="M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z"/></svg></div>
    <span class="logo-text">Attend<span>Track</span></span>
  </a>
  <div class="header-right">
    <nav class="nav-links">
      <a href="/dashboard"          class="nav-btn {% if active=='dashboard' %}active{% endif %}">Dashboard</a>
      <a href="/students"           class="nav-btn {% if active=='students'  %}active{% endif %}">Students</a>
      <a href="/attendance-log"     class="nav-btn {% if active=='log'       %}active{% endif %}">Attendance Log</a>
      <a href="/eligibility-report" class="nav-btn {% if active=='report'    %}active{% endif %}">Report</a>
    </nav>
    <a href="/change-password" class="user-pill">
      <div class="user-avatar-sm">{{ user.full_name[0].upper() if user.full_name else user.username[0].upper() }}</div>
      {{ user.full_name or user.username }}
      {% if user.role == 'admin' %}<span class="admin-badge">Admin</span>{% endif %}
    </a>
    {% if user.role == 'admin' %}
    <a href="/manage-users" class="nav-btn" style="padding:7px 12px;">
      <svg viewBox="0 0 24 24" width="14" height="14" fill="currentColor" style="opacity:.7"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>
      Users
    </a>
    {% endif %}
    <a href="/logout" class="logout-btn">Logout</a>
  </div>
</header>
{% endmacro %}
"""

# ─────────────────────────────────────────
# 13. Templates
# ─────────────────────────────────────────

# ── Portal (role selection) ─────────────
PORTAL_HTML = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>AttendTrack — Sign In</title>
<style>
""" + BASE_STYLE + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f172a 0%,#1e3a8a 50%,#1d4ed8 100%)}
.portal-wrap{width:100%;max-width:520px;padding:24px}
.portal-logo{display:flex;align-items:center;justify-content:center;gap:14px;margin-bottom:40px}
.portal-logo-icon{width:56px;height:56px;background:#fff;border-radius:16px;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 20px rgba(0,0,0,.2)}
.portal-logo-icon svg{width:28px;height:28px;fill:#2563eb}
.portal-logo-text{font-family:'Syne',sans-serif;font-size:28px;font-weight:800;color:#fff;letter-spacing:-.8px}
.portal-logo-text span{color:#93c5fd}
.portal-title{text-align:center;font-family:'Syne',sans-serif;font-size:18px;font-weight:700;color:rgba(255,255,255,.7);margin-bottom:30px;letter-spacing:.5px;text-transform:uppercase}
.portal-cards{display:flex;flex-direction:column;gap:14px}
.portal-card{display:flex;align-items:center;gap:20px;padding:22px 26px;border-radius:16px;text-decoration:none;transition:all .22s;border:2px solid transparent;cursor:pointer}
.portal-card:hover{transform:translateY(-2px);box-shadow:0 12px 40px rgba(0,0,0,.25)}
.portal-card.admin{background:linear-gradient(135deg,#7c3aed,#6d28d9);border-color:rgba(255,255,255,.15)}
.portal-card.teacher{background:linear-gradient(135deg,#0891b2,#0e7490);border-color:rgba(255,255,255,.15)}
.portal-card.student{background:linear-gradient(135deg,#059669,#047857);border-color:rgba(255,255,255,.15)}
.portal-card-icon{width:52px;height:52px;border-radius:14px;background:rgba(255,255,255,.2);display:flex;align-items:center;justify-content:center;flex-shrink:0}
.portal-card-icon svg{width:26px;height:26px;fill:#fff}
.portal-card-info{flex:1}
.portal-card-title{font-family:'Syne',sans-serif;font-size:18px;font-weight:800;color:#fff;letter-spacing:-.4px;margin-bottom:3px}
.portal-card-desc{font-size:13px;color:rgba(255,255,255,.7)}
.portal-card-arrow{font-size:22px;color:rgba(255,255,255,.5);font-weight:300}
.portal-footer{text-align:center;margin-top:28px;font-size:12.5px;color:rgba(255,255,255,.4)}
</style></head>
<body>
<div class="portal-wrap">
  <div class="portal-logo">
    <div class="portal-logo-icon"><svg viewBox="0 0 24 24"><path d="M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z"/></svg></div>
    <span class="portal-logo-text">Attend<span>Track</span></span>
  </div>
  <div class="portal-title">Select your role to continue</div>
  <div class="portal-cards">
    <a href="/login/admin" class="portal-card admin">
      <div class="portal-card-icon">
        <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 4l5 2.18V11c0 3.5-2.33 6.79-5 7.93-2.67-1.14-5-4.43-5-7.93V7.18L12 5z"/></svg>
      </div>
      <div class="portal-card-info">
        <div class="portal-card-title">Admin</div>
        <div class="portal-card-desc">Manage users, view all data & system settings</div>
      </div>
      <div class="portal-card-arrow">→</div>
    </a>
    <a href="/login/teacher" class="portal-card teacher">
      <div class="portal-card-icon">
        <svg viewBox="0 0 24 24"><path d="M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82zM12 3L1 9l11 6 9-4.91V17h2V9L12 3z"/></svg>
      </div>
      <div class="portal-card-info">
        <div class="portal-card-title">Teacher</div>
        <div class="portal-card-desc">Mark attendance, manage students & view reports</div>
      </div>
      <div class="portal-card-arrow">→</div>
    </a>
    <a href="/login/student" class="portal-card student">
      <div class="portal-card-icon">
        <svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
      </div>
      <div class="portal-card-info">
        <div class="portal-card-title">Student</div>
        <div class="portal-card-desc">View your own attendance record & eligibility</div>
      </div>
      <div class="portal-card-arrow">→</div>
    </a>
  </div>
  <div class="portal-footer">AttendTrack — Attendance Management System</div>
</div>
</body></html>
"""

# ── Admin Login ─────────────────────────
LOGIN_ADMIN_HTML = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Admin Login — AttendTrack</title>
<style>
""" + BASE_STYLE + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#2e1065 0%,#7c3aed 50%,#6d28d9 100%)}
.login-wrap{width:100%;max-width:420px;padding:24px}
.login-card{background:#fff;border-radius:20px;padding:40px 36px;box-shadow:0 20px 60px rgba(0,0,0,.25)}
.login-role-badge{display:inline-flex;align-items:center;gap:8px;background:#ede9fe;color:#7c3aed;font-size:12px;font-weight:700;padding:5px 14px;border-radius:99px;margin-bottom:20px;text-transform:uppercase;letter-spacing:.06em}
.login-role-badge svg{width:14px;height:14px;fill:#7c3aed}
.login-logo{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:22px}
.login-logo-icon{width:48px;height:48px;background:#7c3aed;border-radius:12px;display:flex;align-items:center;justify-content:center}
.login-logo-icon svg{width:24px;height:24px;fill:#fff}
.login-logo-text{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--ink);letter-spacing:-.5px}
.login-logo-text span{color:#7c3aed}
.login-title{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--ink);margin-bottom:6px;text-align:center}
.login-sub{font-size:14px;color:var(--ink-muted);text-align:center;margin-bottom:28px}
.login-error{background:var(--danger-light);color:var(--danger);border:1px solid #fca5a5;border-radius:10px;padding:10px 14px;font-size:13.5px;font-weight:500;margin-bottom:18px}
.login-input{width:100%;font-family:'DM Sans',sans-serif;font-size:15px;padding:12px 16px;border:2px solid var(--surface2);border-radius:11px;outline:none;color:var(--ink);background:var(--bg);transition:border-color .18s;margin-bottom:14px}
.login-input:focus{border-color:#7c3aed;background:#fff}
.login-btn{width:100%;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:700;padding:13px;border:none;border-radius:11px;background:#7c3aed;color:#fff;cursor:pointer;transition:all .18s;margin-top:6px}
.login-btn:hover{background:#6d28d9;transform:translateY(-1px);box-shadow:0 6px 20px rgba(124,58,237,.35)}
.login-hint{margin-top:20px;padding:14px;background:var(--bg);border-radius:10px;font-size:12.5px;color:var(--ink-muted)}
.login-hint b{color:var(--ink)}
.cred-chip{display:inline-block;background:#fff;border:1px solid var(--surface2);border-radius:8px;padding:4px 10px;font-family:monospace;font-size:12px;color:var(--ink);margin-top:6px;margin-right:4px}
.back-link{display:block;text-align:center;margin-top:18px;font-size:13px;color:rgba(255,255,255,.65);text-decoration:none}
.back-link:hover{color:#fff}
</style></head>
<body>
<div class="login-wrap">
  <div class="login-card">
    <div style="text-align:center;margin-bottom:10px">
      <div class="login-role-badge">
        <svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4z"/></svg>
        Admin Portal
      </div>
    </div>
    <div class="login-logo">
      <div class="login-logo-icon"><svg viewBox="0 0 24 24"><path d="M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z"/></svg></div>
      <span class="login-logo-text">Attend<span>Track</span></span>
    </div>
    <div class="login-title">Admin Sign In</div>
    <div class="login-sub">Access system settings and full control</div>
    {% if error %}<div class="login-error">{{ error }}</div>{% endif %}
    <form method="post">
      <label style="display:block;font-size:12px;font-weight:600;color:var(--ink-muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px">Username</label>
      <input class="login-input" type="text" name="username" placeholder="Admin username" autofocus required>
      <label style="display:block;font-size:12px;font-weight:600;color:var(--ink-muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px">Password</label>
      <input class="login-input" type="password" name="password" placeholder="Admin password" required>
      <button class="login-btn" type="submit">Sign In as Admin →</button>
    </form>
    <div class="login-hint">
      <b>Default admin credentials</b><br>
      <span class="cred-chip">admin / admin123</span>
    </div>
  </div>
  <a href="/" class="back-link">← Back to role selection</a>
</div>
</body></html>
"""

# ── Teacher Login ────────────────────────
LOGIN_TEACHER_HTML = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Teacher Login — AttendTrack</title>
<style>
""" + BASE_STYLE + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#164e63 0%,#0891b2 50%,#06b6d4 100%)}
.login-wrap{width:100%;max-width:420px;padding:24px}
.login-card{background:#fff;border-radius:20px;padding:40px 36px;box-shadow:0 20px 60px rgba(0,0,0,.25)}
.login-role-badge{display:inline-flex;align-items:center;gap:8px;background:#cffafe;color:#0891b2;font-size:12px;font-weight:700;padding:5px 14px;border-radius:99px;margin-bottom:20px;text-transform:uppercase;letter-spacing:.06em}
.login-role-badge svg{width:14px;height:14px;fill:#0891b2}
.login-logo{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:22px}
.login-logo-icon{width:48px;height:48px;background:#0891b2;border-radius:12px;display:flex;align-items:center;justify-content:center}
.login-logo-icon svg{width:24px;height:24px;fill:#fff}
.login-logo-text{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--ink);letter-spacing:-.5px}
.login-logo-text span{color:#0891b2}
.login-title{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--ink);margin-bottom:6px;text-align:center}
.login-sub{font-size:14px;color:var(--ink-muted);text-align:center;margin-bottom:28px}
.login-error{background:var(--danger-light);color:var(--danger);border:1px solid #fca5a5;border-radius:10px;padding:10px 14px;font-size:13.5px;font-weight:500;margin-bottom:18px}
.login-input{width:100%;font-family:'DM Sans',sans-serif;font-size:15px;padding:12px 16px;border:2px solid var(--surface2);border-radius:11px;outline:none;color:var(--ink);background:var(--bg);transition:border-color .18s;margin-bottom:14px}
.login-input:focus{border-color:#0891b2;background:#fff}
.login-btn{width:100%;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:700;padding:13px;border:none;border-radius:11px;background:#0891b2;color:#fff;cursor:pointer;transition:all .18s;margin-top:6px}
.login-btn:hover{background:#0e7490;transform:translateY(-1px);box-shadow:0 6px 20px rgba(8,145,178,.35)}
.login-hint{margin-top:20px;padding:14px;background:var(--bg);border-radius:10px;font-size:12.5px;color:var(--ink-muted)}
.login-hint b{color:var(--ink)}
.cred-chip{display:inline-block;background:#fff;border:1px solid var(--surface2);border-radius:8px;padding:4px 10px;font-family:monospace;font-size:12px;color:var(--ink);margin-top:6px;margin-right:4px}
.back-link{display:block;text-align:center;margin-top:18px;font-size:13px;color:rgba(255,255,255,.65);text-decoration:none}
.back-link:hover{color:#fff}
</style></head>
<body>
<div class="login-wrap">
  <div class="login-card">
    <div style="text-align:center;margin-bottom:10px">
      <div class="login-role-badge">
        <svg viewBox="0 0 24 24"><path d="M5 13.18v4L12 21l7-3.82v-4L12 17l-7-3.82zM12 3L1 9l11 6 9-4.91V17h2V9L12 3z"/></svg>
        Teacher Portal
      </div>
    </div>
    <div class="login-logo">
      <div class="login-logo-icon"><svg viewBox="0 0 24 24"><path d="M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z"/></svg></div>
      <span class="login-logo-text">Attend<span>Track</span></span>
    </div>
    <div class="login-title">Teacher Sign In</div>
    <div class="login-sub">Mark attendance and manage student records</div>
    {% if error %}<div class="login-error">{{ error }}</div>{% endif %}
    <form method="post">
      <label style="display:block;font-size:12px;font-weight:600;color:var(--ink-muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px">Username</label>
      <input class="login-input" type="text" name="username" placeholder="Teacher username" autofocus required>
      <label style="display:block;font-size:12px;font-weight:600;color:var(--ink-muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px">Password</label>
      <input class="login-input" type="password" name="password" placeholder="Your password" required>
      <button class="login-btn" type="submit">Sign In as Teacher →</button>
    </form>
    <div class="login-hint">
      <b>Default teacher credentials</b><br>
      <span class="cred-chip">teacher / teacher123</span>
    </div>
  </div>
  <a href="/" class="back-link">← Back to role selection</a>
</div>
</body></html>
"""

# ── Student Login ────────────────────────
LOGIN_STUDENT_HTML = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Student Login — AttendTrack</title>
<style>
""" + BASE_STYLE + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#064e3b 0%,#059669 50%,#10b981 100%)}
.login-wrap{width:100%;max-width:420px;padding:24px}
.login-card{background:#fff;border-radius:20px;padding:40px 36px;box-shadow:0 20px 60px rgba(0,0,0,.25)}
.login-role-badge{display:inline-flex;align-items:center;gap:8px;background:#d1fae5;color:#059669;font-size:12px;font-weight:700;padding:5px 14px;border-radius:99px;margin-bottom:20px;text-transform:uppercase;letter-spacing:.06em}
.login-role-badge svg{width:14px;height:14px;fill:#059669}
.login-logo{display:flex;align-items:center;justify-content:center;gap:12px;margin-bottom:22px}
.login-logo-icon{width:48px;height:48px;background:#059669;border-radius:12px;display:flex;align-items:center;justify-content:center}
.login-logo-icon svg{width:24px;height:24px;fill:#fff}
.login-logo-text{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--ink);letter-spacing:-.5px}
.login-logo-text span{color:#059669}
.login-title{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;color:var(--ink);margin-bottom:6px;text-align:center}
.login-sub{font-size:14px;color:var(--ink-muted);text-align:center;margin-bottom:28px}
.login-error{background:var(--danger-light);color:var(--danger);border:1px solid #fca5a5;border-radius:10px;padding:10px 14px;font-size:13.5px;font-weight:500;margin-bottom:18px}
.login-input{width:100%;font-family:'DM Sans',sans-serif;font-size:15px;padding:12px 16px;border:2px solid var(--surface2);border-radius:11px;outline:none;color:var(--ink);background:var(--bg);transition:border-color .18s;margin-bottom:14px}
.login-input:focus{border-color:#059669;background:#fff}
.login-btn{width:100%;font-family:'DM Sans',sans-serif;font-size:15px;font-weight:700;padding:13px;border:none;border-radius:11px;background:#059669;color:#fff;cursor:pointer;transition:all .18s;margin-top:6px}
.login-btn:hover{background:#047857;transform:translateY(-1px);box-shadow:0 6px 20px rgba(5,150,105,.35)}
.login-info{margin-top:20px;padding:14px;background:#f0fdf4;border:1px solid #a7f3d0;border-radius:10px;font-size:12.5px;color:#065f46}
.back-link{display:block;text-align:center;margin-top:18px;font-size:13px;color:rgba(255,255,255,.65);text-decoration:none}
.back-link:hover{color:#fff}
</style></head>
<body>
<div class="login-wrap">
  <div class="login-card">
    <div style="text-align:center;margin-bottom:10px">
      <div class="login-role-badge">
        <svg viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
        Student Portal
      </div>
    </div>
    <div class="login-logo">
      <div class="login-logo-icon"><svg viewBox="0 0 24 24"><path d="M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z"/></svg></div>
      <span class="login-logo-text">Attend<span>Track</span></span>
    </div>
    <div class="login-title">Student Sign In</div>
    <div class="login-sub">View your attendance record and eligibility</div>
    {% if error %}<div class="login-error">{{ error }}</div>{% endif %}
    <form method="post">
      <label style="display:block;font-size:12px;font-weight:600;color:var(--ink-muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px">Roll Number</label>
      <input class="login-input" type="text" name="roll_no" placeholder="Enter your roll number" autofocus required>
      <label style="display:block;font-size:12px;font-weight:600;color:var(--ink-muted);text-transform:uppercase;letter-spacing:.07em;margin-bottom:6px">Password</label>
      <input class="login-input" type="password" name="password" placeholder="Your password" required>
      <button class="login-btn" type="submit">View My Attendance →</button>
    </form>
    <div class="login-info">
      💡 Your password is set by your teacher when you are added to the system. Contact your teacher if you need access.
    </div>
  </div>
  <a href="/" class="back-link">← Back to role selection</a>
</div>
</body></html>
"""

# ── Student Portal (own attendance view) ─
STUDENT_PORTAL_HTML = """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>My Attendance — AttendTrack</title>
<style>
""" + BASE_STYLE + """
.student-header{background:linear-gradient(135deg,#064e3b,#059669);border-radius:var(--radius);padding:28px 30px;margin-bottom:24px;color:#fff;display:flex;align-items:center;gap:20px;box-shadow:var(--shadow-lg)}
.student-header-avatar{width:64px;height:64px;border-radius:50%;background:rgba(255,255,255,.2);display:flex;align-items:center;justify-content:center;font-family:'Syne',sans-serif;font-size:26px;font-weight:800;color:#fff;flex-shrink:0}
.student-header-name{font-family:'Syne',sans-serif;font-size:22px;font-weight:800;letter-spacing:-.5px;margin-bottom:4px}
.student-header-meta{font-size:13.5px;opacity:.8;display:flex;gap:16px;flex-wrap:wrap}
.student-header-meta span{display:flex;align-items:center;gap:5px}
.student-header-right{margin-left:auto;text-align:right}
.student-pct-big{font-family:'Syne',sans-serif;font-size:42px;font-weight:800;line-height:1;color:#fff}
.student-pct-lbl{font-size:12px;opacity:.75;text-transform:uppercase;letter-spacing:.06em;margin-top:2px}
.pct-bar-outer{height:8px;background:rgba(255,255,255,.25);border-radius:99px;margin-top:8px;overflow:hidden;min-width:120px}
.pct-bar-inner{height:100%;background:#fff;border-radius:99px;transition:width .7s cubic-bezier(.4,0,.2,1)}
.student-nav{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.student-nav-title{font-family:'Syne',sans-serif;font-size:16px;font-weight:700}
.student-logout{font-size:12px;font-weight:600;padding:6px 14px;border-radius:8px;border:1.5px solid var(--surface2);background:var(--surface);color:var(--ink-muted);text-decoration:none;transition:all .18s}
.student-logout:hover{background:var(--danger-light);color:var(--danger);border-color:#fca5a5}
</style></head>
<body>
<div class="page-wrapper">
  <!-- Simple student nav -->
  <header class="site-header">
    <a href="/student-portal" class="logo">
      <div class="logo-icon" style="background:#059669"><svg viewBox="0 0 24 24"><path d="M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z"/></svg></div>
      <span class="logo-text">Attend<span style="color:#059669">Track</span></span>
    </a>
    <div class="header-right">
      <div class="user-pill" style="border-color:#a7f3d0">
        <div class="user-avatar-sm" style="background:#059669">{{ student[1][0].upper() }}</div>
        {{ student[1] }}
        <span style="font-size:10px;font-weight:700;padding:1px 6px;border-radius:99px;background:#d1fae5;color:#065f46">Student</span>
      </div>
      <a href="/logout" class="logout-btn">Logout</a>
    </div>
  </header>

  <!-- Profile header -->
  <div class="student-header">
    <div class="student-header-avatar">{{ student[1][0].upper() }}</div>
    <div>
      <div class="student-header-name">{{ student[1] }}</div>
      <div class="student-header-meta">
        <span>🎓 Roll No: {{ student[2] or '—' }}</span>
        <span>🏫 {{ student[3] or 'No Department' }}</span>
      </div>
    </div>
    <div class="student-header-right">
      <div class="student-pct-big">{{ pct }}%</div>
      <div class="student-pct-lbl">Attendance</div>
      <div class="pct-bar-outer"><div class="pct-bar-inner" style="width:{{ pct }}%"></div></div>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats-row">
    <div class="stat-card accent">
      <div class="stat-value">{{ total }}</div>
      <div class="stat-label">Total Classes</div>
    </div>
    <div class="stat-card success">
      <div class="stat-value">{{ present }}</div>
      <div class="stat-label">Present</div>
    </div>
    <div class="stat-card danger">
      <div class="stat-value">{{ absent }}</div>
      <div class="stat-label">Absent</div>
    </div>
  </div>

  <!-- Eligibility notice -->
  {% if total > 0 %}
  {% if pct >= 75 %}
  <div class="flash success" style="display:flex;align-items:center;gap:10px">
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
    <span><b>Eligible for exam!</b> Your attendance ({{ pct }}%) meets the 75% requirement.</span>
  </div>
  {% elif pct >= 60 %}
  <div class="flash" style="background:#fef3c7;color:#92400e;border:1px solid #fde68a;display:flex;align-items:center;gap:10px">
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M1 21h22L12 2 1 21zm12-3h-2v-2h2v2zm0-4h-2v-4h2v4z"/></svg>
    <span><b>At risk!</b> Your attendance is {{ pct }}%. You need 75% to be eligible.</span>
  </div>
  {% else %}
  <div class="flash error" style="display:flex;align-items:center;gap:10px">
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
    <span><b>Not eligible.</b> Your attendance ({{ pct }}%) is critically low. Contact your teacher.</span>
  </div>
  {% endif %}
  {% endif %}

  <!-- Attendance records -->
  <div class="history-card">
    <div class="history-header">
      <div class="history-title">Attendance History</div>
      <div class="filter-btns">
        <button class="filter-btn active-all" onclick="filterRecs('all',this)">All ({{ total }})</button>
        <button class="filter-btn" onclick="filterRecs('present',this)">Present ({{ present }})</button>
        <button class="filter-btn" onclick="filterRecs('absent',this)">Absent ({{ absent }})</button>
      </div>
    </div>
    {% if records %}
    <div id="recList">
      {% for r in records %}
      <div class="record-row" data-status="{{ r.status.lower() }}">
        <div class="record-date">
          <div class="date-icon {{ r.status.lower() }}">
            {% if r.status == 'Present' %}✓{% else %}✗{% endif %}
          </div>
          <div>
            <div class="date-text">{{ r.date_fmt }}</div>
            <div class="date-day">{{ r.day }}</div>
          </div>
        </div>
        <span class="status-tag {{ r.status.lower() }}">{{ r.status }}</span>
      </div>
      {% endfor %}
    </div>
    {% else %}
    <div class="empty-state" style="padding:40px">
      <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z"/></svg>
      <p>No attendance records yet.</p>
    </div>
    {% endif %}
  </div>
</div>
<script>
function filterRecs(f,btn){
  document.querySelectorAll('.filter-btn').forEach(b=>{b.className='filter-btn'});
  btn.className='filter-btn active-'+f;
  document.querySelectorAll('#recList .record-row').forEach(r=>{
    r.style.display=(f==='all'||r.dataset.status===f)?'flex':'none';
  });
}
</script>
</body></html>
"""

CHANGE_PW_HTML = NAV_MACRO + """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Change Password — AttendTrack</title>
<style>""" + BASE_STYLE + """</style></head>
<body><div class="page-wrapper">
{{ navbar('') }}
<div class="page-hero"><h1>Account Settings</h1><p>Update your login password.</p></div>
{% if msg %}<div class="flash success">{{ msg }}</div>{% endif %}
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}
<div class="card" style="max-width:440px">
  <div class="card-title">Change Password</div>
  <form method="post">
    <div class="form-group">
      <label class="form-label">Current Password</label>
      <input class="form-input" type="password" name="old_password" required>
    </div>
    <div class="form-group">
      <label class="form-label">New Password</label>
      <input class="form-input" type="password" name="new_password" required>
    </div>
    <div class="form-group">
      <label class="form-label">Confirm New Password</label>
      <input class="form-input" type="password" name="confirm_password" required>
    </div>
    <div style="display:flex;gap:10px;margin-top:4px">
      <a href="/dashboard" class="btn btn-ghost" style="flex:1;justify-content:center">Cancel</a>
      <button type="submit" class="btn btn-primary" style="flex:2;justify-content:center">Update Password</button>
    </div>
  </form>
</div>
</div></body></html>
"""

MANAGE_USERS_HTML = NAV_MACRO + """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Manage Users — AttendTrack</title>
<style>""" + BASE_STYLE + """
.role-badge{font-size:11px;font-weight:700;padding:2px 9px;border-radius:99px}
.role-admin{background:#ede9fe;color:#7c3aed}
.role-teacher{background:var(--accent-light);color:var(--accent)}
</style></head>
<body><div class="page-wrapper">
{{ navbar('') }}
<div class="page-hero"><h1>User Management</h1><p>Admin-only: add or remove system users.</p></div>
{% if msg %}<div class="flash success">{{ msg }}</div>{% endif %}
{% if error %}<div class="flash error">{{ error }}</div>{% endif %}

<div class="card">
  <div class="card-title">Add New User</div>
  <form method="post">
    <input type="hidden" name="action" value="add">
    <div class="form-row">
      <div class="form-group"><label class="form-label">Full Name</label><input class="form-input" name="full_name" placeholder="e.g. Dr. Sharma" required></div>
      <div class="form-group"><label class="form-label">Username</label><input class="form-input" name="username" placeholder="e.g. sharma" required></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label class="form-label">Password</label><input class="form-input" type="password" name="password" placeholder="Min 6 characters" required></div>
      <div class="form-group"><label class="form-label">Role</label>
        <select class="form-input" name="role">
          <option value="teacher">Teacher</option>
          <option value="admin">Admin</option>
        </select>
      </div>
    </div>
    <button class="btn btn-primary" type="submit">
      <svg viewBox="0 0 24 24" width="14" height="14" fill="white"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>
      Add User
    </button>
  </form>
</div>

<div class="card" style="padding:0;overflow:hidden">
  <table class="data-table">
    <thead><tr><th>#</th><th>Full Name</th><th>Username</th><th>Role</th><th style="text-align:right">Actions</th></tr></thead>
    <tbody>
    {% for u in users %}
    <tr>
      <td style="color:var(--ink-muted)">{{ u[0] }}</td>
      <td style="font-weight:500">{{ u[3] or '—' }}</td>
      <td><code style="font-size:13px">{{ u[1] }}</code></td>
      <td><span class="role-badge role-{{ u[2] }}">{{ u[2] }}</span></td>
      <td style="text-align:right">
        {% if u[0] != user.id %}
        <form method="post" onsubmit="return confirm('Delete user {{ u[1] }}?')" style="display:inline">
          <input type="hidden" name="action" value="delete">
          <input type="hidden" name="uid" value="{{ u[0] }}">
          <button type="submit" class="btn btn-danger btn-sm">Delete</button>
        </form>
        {% else %}
        <span style="font-size:12px;color:var(--ink-muted)">(you)</span>
        {% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
</div></body></html>
"""

ADD_STUDENT_HTML = NAV_MACRO + """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Students — AttendTrack</title>
<style>""" + BASE_STYLE + """</style></head>
<body><div class="page-wrapper">
{{ navbar('students') }}
<div class="page-hero"><h1>Students</h1><p>Add students and manage their records.</p></div>

<div class="card">
  <div class="card-title">Add New Student</div>
  <form method="post">
    <div class="form-row">
      <div class="form-group"><label class="form-label">Full Name</label><input class="form-input" name="name" placeholder="e.g. Ravi Kumar" required autofocus></div>
      <div class="form-group"><label class="form-label">Roll No</label><input class="form-input" name="roll_no" placeholder="e.g. CS2024001"></div>
    </div>
    <div class="form-row">
      <div class="form-group"><label class="form-label">Department</label><input class="form-input" name="department" placeholder="e.g. Computer Science"></div>
      <div class="form-group"><label class="form-label">Student Login Password</label><input class="form-input" type="password" name="student_password" placeholder="Password for student portal"></div>
    </div>
    <p style="font-size:12px;color:var(--ink-muted);margin-bottom:12px">💡 The student will use their Roll No + this password to log in to the student portal.</p>
    <button type="submit" class="btn btn-primary">
      <svg viewBox="0 0 24 24" width="14" height="14" fill="white"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>
      Add Student
    </button>
  </form>
</div>

{% if students %}
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px">
  <h2 style="font-family:'Syne',sans-serif;font-size:16px;font-weight:700">All Students ({{ students|length }})</h2>
</div>
<ul class="student-list">
{% for s in students %}
<li class="student-item" style="animation-delay:{{ loop.index0 * 0.04 }}s">
  <div class="student-info">
    <div class="student-avatar">{{ s[1][0].upper() if s[1] else '?' }}</div>
    <div>
      <div class="student-name">{{ s[1] }}</div>
      <div class="student-meta">
        {% if s[2] %}Roll: {{ s[2]}}{% endif %}
        {% if s[3] %} · {{ s[3] }}{% endif %}
        {% if s[4] %} · <span style="color:var(--success);font-weight:600">✓ Portal access</span>{% else %} · <span style="color:var(--warning)">No portal password</span>{% endif %}
      </div>
    </div>
  </div>
  <div style="display:flex;gap:8px;align-items:center;flex-shrink:0">
    <a href="/mark/{{ s[0] }}" class="btn btn-success btn-sm">Mark</a>
    <a href="/student/{{ s[0] }}" class="btn btn-ghost btn-sm">View</a>
    <form method="post" action="/delete/{{ s[0] }}" onsubmit="return confirm('Delete {{ s[1] }} and all attendance?')" style="display:inline">
      <button type="submit" class="btn btn-danger btn-sm">✕</button>
    </form>
  </div>
</li>
{% endfor %}
</ul>
{% else %}
<div class="card"><div class="empty-state">
  <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>
  <p>No students yet. Add your first student above.</p>
</div></div>
{% endif %}
</div></body></html>
"""

MARK_ATTENDANCE_HTML = NAV_MACRO + """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Mark Attendance — AttendTrack</title>
<style>""" + BASE_STYLE + """</style></head>
<body><div class="page-wrapper">
{{ navbar('students') }}
<div class="page-hero">
  <h1>Mark Attendance</h1>
  <p>Recording for <strong>{{ student[1] }}</strong> · {{ now }}</p>
</div>
<div class="card" style="max-width:480px">
  <form method="post">
    <div class="form-group">
      <label class="form-label">Date</label>
      <input class="form-input" type="date" name="date" value="{{ today_iso }}" max="{{ today_iso }}" required>
    </div>
    <div class="form-group">
      <label class="form-label">Status</label>
      <div class="attendance-options">
        <input class="attendance-radio" type="radio" name="status" id="present" value="Present" checked>
        <label class="attendance-label" for="present">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
          Present
        </label>
        <input class="attendance-radio" type="radio" name="status" id="absent" value="Absent">
        <label class="attendance-label" for="absent">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
          Absent
        </label>
      </div>
    </div>
    <div style="display:flex;gap:10px">
      <a href="/students" class="btn btn-ghost" style="flex:1;justify-content:center">Cancel</a>
      <button type="submit" class="btn btn-primary" style="flex:2;justify-content:center">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="white"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
        Save Attendance
      </button>
    </div>
  </form>
</div>
</div></body></html>
"""

STUDENT_DETAIL_HTML = NAV_MACRO + """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{{ student[1] }} — AttendTrack</title>
<style>""" + BASE_STYLE + """</style></head>
<body><div class="page-wrapper">
{{ navbar('students') }}

<div class="profile-card">
  <div class="profile-avatar">{{ student[1][0].upper() }}</div>
  <div class="profile-info">
    <div class="profile-name">{{ student[1] }}</div>
    <div class="profile-meta">
      {% if student[2] %}Roll No: {{ student[2] }}{% endif %}
      {% if student[3] %} · {{ student[3] }}{% endif %}
    </div>
    <div style="margin-top:10px">
      <div class="progress-bar-wrap">
        <div class="progress-bar-bg">
          <div class="progress-bar-fill" style="width:{{ pct }}%;background:{% if pct>=75 %}var(--success){% elif pct>=60 %}var(--warning){% else %}var(--danger){% endif %}"></div>
        </div>
        <span class="badge {% if pct>=75 %}badge-high{% elif pct>=60 %}badge-mid{% else %}badge-low{% endif %}">{{ pct }}%</span>
      </div>
    </div>
  </div>
  <div class="profile-stats">
    <div class="p-stat"><div class="p-stat-val" style="color:var(--success)">{{ present }}</div><div class="p-stat-lbl">Present</div></div>
    <div class="p-stat"><div class="p-stat-val" style="color:var(--danger)">{{ absent }}</div><div class="p-stat-lbl">Absent</div></div>
    <div class="p-stat"><div class="p-stat-val">{{ total }}</div><div class="p-stat-lbl">Total</div></div>
  </div>
</div>

<div style="display:flex;gap:10px;margin-bottom:22px">
  <a href="/mark/{{ student[0] }}" class="btn btn-primary">
    <svg viewBox="0 0 24 24" width="14" height="14" fill="white"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
    Mark Attendance
  </a>
  <a href="/students" class="btn btn-ghost">← All Students</a>
</div>

<div class="history-card">
  <div class="history-header">
    <div class="history-title">Attendance History</div>
    <div class="filter-btns">
      <button class="filter-btn active-all" onclick="filterRecs('all',this)">All</button>
      <button class="filter-btn" onclick="filterRecs('present',this)">Present</button>
      <button class="filter-btn" onclick="filterRecs('absent',this)">Absent</button>
    </div>
  </div>
  {% if records %}
  <div id="recList">
    {% for r in records %}
    <div class="record-row" data-status="{{ r.status.lower() }}">
      <div class="record-date">
        <div class="date-icon {{ r.status.lower() }}">
          {% if r.status == 'Present' %}✓{% else %}✗{% endif %}
        </div>
        <div>
          <div class="date-text">{{ r.date_fmt }}</div>
          <div class="date-day">{{ r.day }}</div>
        </div>
      </div>
      <span class="status-tag {{ r.status.lower() }}">{{ r.status }}</span>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="empty-state" style="padding:40px"><p>No records yet.</p></div>
  {% endif %}
</div>
</div>
<script>
function filterRecs(f,btn){
  document.querySelectorAll('.filter-btn').forEach(b=>{b.className='filter-btn'});
  btn.className='filter-btn active-'+f;
  document.querySelectorAll('#recList .record-row').forEach(r=>{
    r.style.display=(f==='all'||r.dataset.status===f)?'flex':'none';
  });
}
</script>
</body></html>
"""

ATTENDANCE_LOG_HTML = NAV_MACRO + """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Attendance Log — AttendTrack</title>
<style>""" + BASE_STYLE + """</style></head>
<body><div class="page-wrapper">
{{ navbar('log') }}
<div class="page-hero"><h1>Attendance Log</h1><p>Full date-wise attendance matrix for all students.</p></div>

{% if students and dates %}
<div class="log-table-wrap">
<table class="log-table">
  <thead>
    <tr>
      <th>Student</th>
      {% for d in dates[:20] %}
      <th style="text-align:center;white-space:nowrap">
        {{ d[5:] }}
      </th>
      {% endfor %}
      <th style="text-align:center">%</th>
    </tr>
  </thead>
  <tbody>
  {% for s in students %}
  {% set sid = s[0] %}
  <tr>
    <td>
      <div style="display:flex;align-items:center;gap:8px">
        <div class="student-avatar" style="width:28px;height:28px;font-size:10px;flex-shrink:0">{{ s[1][0].upper() }}</div>
        <a href="/student/{{ sid }}" style="font-weight:500;text-decoration:none;color:var(--ink)">{{ s[1] }}</a>
      </div>
    </td>
    {% set ns = namespace(p=0,t=0) %}
    {% for d in dates[:20] %}
    {% set st = lookup.get(d, {}).get(sid) %}
    {% if st %}{% set ns.t = ns.t+1 %}{% if st=='Present' %}{% set ns.p = ns.p+1 %}{% endif %}{% endif %}
    <td style="text-align:center">
      {% if st == 'Present' %}<span class="dot-present">✓</span>
      {% elif st == 'Absent' %}<span class="dot-absent">✗</span>
      {% else %}<span class="dot-none">—</span>{% endif %}
    </td>
    {% endfor %}
    <td style="text-align:center">
      {% if ns.t > 0 %}
      {% set pct2 = (ns.p/ns.t*100)|round(0)|int %}
      <span class="pct-pill {% if pct2>=75 %}pct-high{% elif pct2>=60 %}pct-mid{% else %}pct-low{% endif %}">{{ pct2 }}%</span>
      {% else %}—{% endif %}
    </td>
  </tr>
  {% endfor %}
  </tbody>
</table>
</div>
{% if dates|length > 20 %}
<p style="margin-top:12px;font-size:13px;color:var(--ink-muted);text-align:center">Showing latest 20 of {{ dates|length }} dates.</p>
{% endif %}
{% else %}
<div class="card"><div class="empty-state">
  <svg viewBox="0 0 24 24" fill="currentColor"><path d="M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z"/></svg>
  <p>No attendance data yet. <a href="/students" style="color:var(--accent)">Add students</a> and mark attendance.</p>
</div></div>
{% endif %}
</div></body></html>
"""

DASHBOARD_HTML = NAV_MACRO + """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Dashboard — AttendTrack</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<style>""" + BASE_STYLE + """</style></head>
<body><div class="page-wrapper">
{{ navbar('dashboard') }}
<div class="page-hero"><h1>Dashboard</h1><p>Overview of attendance across all students.</p></div>

<div class="stats-row">
  <div class="stat-card accent"><div class="stat-value">{{ total_students }}</div><div class="stat-label">Total Students</div></div>
  <div class="stat-card success"><div class="stat-value">{{ total_present }}</div><div class="stat-label">Total Present</div></div>
  <div class="stat-card danger"><div class="stat-value">{{ total_absent }}</div><div class="stat-label">Total Absent</div></div>
</div>

<div class="dashboard-grid">
  <div class="chart-card" style="animation-delay:.05s">
    <div class="chart-title">Overall Attendance</div>
    {% set tr=total_present+total_absent %}
    {% if tr>0 %}
    <div class="pie-wrap">
      <div class="pie-canvas-wrap">
        <canvas id="overallPie"></canvas>
        <div class="pie-center-label">
          <div class="pie-center-num">{{ ((total_present/tr)*100)|round(0)|int }}%</div>
          <div class="pie-center-sub">Overall</div>
        </div>
      </div>
      <div class="pie-legend">
        <div class="legend-item"><div class="legend-dot" style="background:#059669"></div><div><div class="legend-label">Present</div><div class="legend-val" style="color:var(--success)">{{ total_present }}</div></div></div>
        <div class="legend-item"><div class="legend-dot" style="background:#dc2626"></div><div><div class="legend-label">Absent</div><div class="legend-val" style="color:var(--danger)">{{ total_absent }}</div></div></div>
        <div class="legend-item"><div class="legend-dot" style="background:#e8eef5;border:1px solid #ccc"></div><div><div class="legend-label">Total</div><div class="legend-val">{{ tr }}</div></div></div>
      </div>
    </div>
    {% else %}<div class="empty-state"><p>No attendance data yet.</p></div>{% endif %}
  </div>

  <div class="chart-card" style="animation-delay:.1s">
    <div class="chart-title">Today's Summary</div>
    <div class="today-badge"><svg viewBox="0 0 24 24" width="11" height="11" fill="currentColor"><path d="M17 12h-5v5h5v-5zM16 1v2H8V1H6v2H5c-1.11 0-1.99.9-1.99 2L3 19c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2h-1V1h-2zm3 18H5V8h14v11z"/></svg> {{ today_fmt }}</div>
    <div class="today-row">
      <div class="today-stat present-card">
        <div class="today-stat-icon"><svg viewBox="0 0 24 24"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg></div>
        <div><div class="today-stat-num">{{ today_present }}</div><div class="today-stat-lbl">Present Today</div></div>
      </div>
      <div class="today-stat absent-card">
        <div class="today-stat-icon"><svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg></div>
        <div><div class="today-stat-num">{{ today_absent }}</div><div class="today-stat-lbl">Absent Today</div></div>
      </div>
    </div>
    {% set tt=today_present+today_absent %}
    {% if tt>0 %}<div style="margin-top:16px"><canvas id="todayPie" height="110"></canvas></div>{% endif %}
  </div>

  <div class="chart-card full" style="animation-delay:.15s">
    <div class="chart-title">Per-Student Breakdown</div>
    {% if student_data %}<div style="position:relative;height:220px"><canvas id="studentBar"></canvas></div>
    {% else %}<div class="empty-state"><p>No data yet.</p></div>{% endif %}
  </div>
</div>

<div class="chart-card" style="animation-delay:.2s">
  <div class="chart-title">Recent Activity</div>
  {% if recent %}
  <ul class="activity-list">
    {% for r in recent %}
    <li class="activity-item">
      <div style="display:flex;align-items:center;gap:9px">
        <div class="student-avatar" style="width:30px;height:30px;font-size:11px;flex-shrink:0">{{ r[0][0].upper() }}</div>
        <div><div class="activity-name">{{ r[0] }}</div><div class="activity-date">{{ r[1] }}</div></div>
      </div>
      <span class="status-pill {{ r[2].lower() }}">{{ r[2] }}</span>
    </li>
    {% endfor %}
  </ul>
  {% else %}<div class="empty-state" style="padding:24px"><p>No activity yet.</p></div>{% endif %}
</div>

<script>
Chart.defaults.font.family='DM Sans';
Chart.defaults.plugins.legend.display=false;
{% set tr=total_present+total_absent %}
{% if tr>0 %}
new Chart(document.getElementById('overallPie'),{type:'doughnut',data:{labels:['Present','Absent'],datasets:[{data:[{{total_present}},{{total_absent}}],backgroundColor:['#059669','#dc2626'],borderColor:'#fff',borderWidth:3,hoverOffset:6}]},options:{cutout:'68%',animation:{duration:900,easing:'easeOutQuart'},plugins:{tooltip:{callbacks:{label:ctx=>' '+ctx.label+': '+ctx.raw}}}}});
{% endif %}
{% set tt=today_present+today_absent %}
{% if tt>0 %}
new Chart(document.getElementById('todayPie'),{type:'doughnut',data:{labels:['Present','Absent'],datasets:[{data:[{{today_present}},{{today_absent}}],backgroundColor:['#059669','#dc2626'],borderColor:'#fff',borderWidth:3}]},options:{cutout:'60%',animation:{duration:800},plugins:{legend:{display:true,position:'right',labels:{boxWidth:11,padding:14,font:{size:12}}},tooltip:{callbacks:{label:ctx=>' '+ctx.label+': '+ctx.raw}}}}});
{% endif %}
{% if student_data %}
new Chart(document.getElementById('studentBar'),{type:'bar',data:{labels:[{% for s in student_data %}'{{s[0]}}'{% if not loop.last %},{% endif %}{% endfor %}],datasets:[{label:'Present',data:[{% for s in student_data %}{{s[1] or 0}}{% if not loop.last %},{% endif %}{% endfor %}],backgroundColor:'#059669',borderRadius:5,borderSkipped:false},{label:'Absent',data:[{% for s in student_data %}{{s[2] or 0}}{% if not loop.last %},{% endif %}{% endfor %}],backgroundColor:'#dc2626',borderRadius:5,borderSkipped:false}]},options:{responsive:true,maintainAspectRatio:false,animation:{duration:900,easing:'easeOutQuart'},scales:{x:{grid:{display:false},ticks:{font:{size:12}}},y:{grid:{color:'#e8eef5'},beginAtZero:true,ticks:{precision:0,font:{size:11}}}},plugins:{legend:{display:true,position:'top',align:'end',labels:{boxWidth:11,padding:14,font:{size:12}}}}}});
{% endif %}
</script>
</div></body></html>
"""

REPORT_HTML = NAV_MACRO + """
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Eligibility Report — AttendTrack</title>
<style>""" + BASE_STYLE + """</style></head>
<body><div class="page-wrapper">
{{ navbar('report') }}
<div class="page-hero"><h1>Eligibility Report</h1><p>Exam eligibility status based on attendance threshold.</p></div>

<div class="threshold-bar">
  <span style="font-size:13px;font-weight:600;color:var(--ink-muted);white-space:nowrap">Min. Threshold</span>
  <input type="range" class="threshold-slider" id="ts" min="50" max="90" step="5" value="{{ threshold }}" style="--val:{{ threshold }}%">
  <span class="threshold-val" id="tv">{{ threshold }}%</span>
  <a href="/eligibility-report?threshold={{ threshold }}" id="applyBtn" class="btn btn-primary btn-sm">Apply</a>
</div>

<div class="risk-summary">
  <div class="risk-stat all"><div class="risk-stat-num">{{ total_count }}</div><div class="risk-stat-lbl">Total</div></div>
  <div class="risk-stat safe"><div class="risk-stat-num">{{ safe_count }}</div><div class="risk-stat-lbl">✓ Safe</div></div>
  <div class="risk-stat warning"><div class="risk-stat-num">{{ warning_count }}</div><div class="risk-stat-lbl">⚠ At Risk</div></div>
  <div class="risk-stat critical"><div class="risk-stat-num">{{ critical_count }}</div><div class="risk-stat-lbl">✗ Critical</div></div>
</div>

{% if students_data %}
{% set criticals=students_data|selectattr("risk","eq","critical")|list %}
{% if criticals %}
<div class="section-heading"><span class="dot-c"></span> Critical — Below {{ threshold-15 }}%</div>
{% for s in criticals %}
<div class="defaulter-row critical" style="animation-delay:{{ loop.index*0.04 }}s">
  <div class="def-avatar">{{ s.name[0].upper() }}</div>
  <div class="def-main">
    <div class="def-name">{{ s.name }}</div>
    <div class="def-bar-wrap"><div class="def-bar-bg"><div class="def-bar-fill" style="width:{{ s.pct }}%"></div></div><span class="def-pct">{{ s.pct }}%</span></div>
  </div>
  <div class="def-stats">
    <span class="def-counts">P:<span>{{ s.present }}</span> A:<span>{{ s.absent }}</span> T:<span>{{ s.total }}</span></span>
    <span class="need-badge">{% if s.classes_needed>0 %}Need {{ s.classes_needed }} more class{{ 'es' if s.classes_needed>1 }}{% else %}Eligible{% endif %}</span>
  </div>
</div>{% endfor %}{% endif %}

{% set warnings=students_data|selectattr("risk","eq","warning")|list %}
{% if warnings %}
<div class="section-heading" style="margin-top:24px"><span class="dot-w"></span> At Risk — {{ threshold-15 }}% to {{ threshold }}%</div>
{% for s in warnings %}
<div class="defaulter-row warning" style="animation-delay:{{ loop.index*0.04 }}s">
  <div class="def-avatar">{{ s.name[0].upper() }}</div>
  <div class="def-main">
    <div class="def-name">{{ s.name }}</div>
    <div class="def-bar-wrap"><div class="def-bar-bg"><div class="def-bar-fill" style="width:{{ s.pct }}%"></div></div><span class="def-pct">{{ s.pct }}%</span></div>
  </div>
  <div class="def-stats">
    <span class="def-counts">P:<span>{{ s.present }}</span> A:<span>{{ s.absent }}</span> T:<span>{{ s.total }}</span></span>
    <span class="need-badge">{% if s.classes_needed>0 %}Need {{ s.classes_needed }} more class{{ 'es' if s.classes_needed>1 }}{% else %}Eligible{% endif %}</span>
  </div>
</div>{% endfor %}{% endif %}

{% set safes=students_data|selectattr("risk","eq","safe")|list %}
{% if safes %}
<div class="section-heading" style="margin-top:24px"><span class="dot-s"></span> Safe — Above {{ threshold }}%</div>
{% for s in safes %}
<div class="defaulter-row safe" style="animation-delay:{{ loop.index*0.04 }}s">
  <div class="def-avatar">{{ s.name[0].upper() }}</div>
  <div class="def-main">
    <div class="def-name">{{ s.name }}</div>
    <div class="def-bar-wrap"><div class="def-bar-bg"><div class="def-bar-fill" style="width:{{ s.pct }}%"></div></div><span class="def-pct">{{ s.pct }}%</span></div>
  </div>
  <div class="def-stats">
    <span class="def-counts">P:<span>{{ s.present }}</span> A:<span>{{ s.absent }}</span> T:<span>{{ s.total }}</span></span>
    <span class="need-badge">✓ Eligible</span>
  </div>
</div>{% endfor %}{% endif %}

{% else %}
<div class="card"><div class="empty-state">
  <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16 11c1.66 0 2.99-1.34 2.99-3S17.66 5 16 5c-1.66 0-3 1.34-3 3s1.34 3 3 3zm-8 0c1.66 0 2.99-1.34 2.99-3S9.66 5 8 5C6.34 5 5 6.34 5 8s1.34 3 3 3zm0 2c-2.33 0-7 1.17-7 3.5V19h14v-2.5c0-2.33-4.67-3.5-7-3.5z"/></svg>
  <p>No students yet. <a href="/students" style="color:var(--accent)">Add students</a> to get started.</p>
</div></div>{% endif %}

<script>
const ts=document.getElementById('ts'),tv=document.getElementById('tv'),ab=document.getElementById('applyBtn');
ts.addEventListener('input',function(){tv.textContent=this.value+'%';this.style.setProperty('--val',this.value+'%');ab.href='/eligibility-report?threshold='+this.value;});
</script>
</div></body></html>
"""

# ─────────────────────────────────────────
# 14. Run
# ─────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)