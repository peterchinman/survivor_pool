import os
import re

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, make_response, redirect, render_template, request, session, url_for
from flask_session import Session
from slugify import slugify
from urllib.parse import urlparse
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required, admin_required

# Configure application
app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
if (__name__ == "__main__"):
    app.run(debug=True)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///survivor.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/init_db", methods=["GET"])
def init_db():
    #create tables
    error = False
    if not db.execute("""
        CREATE TABLE user (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            is_site_admin BOOLEAN NOT NULL
        )
    """):
        flash("Error creating table", "error")
        error = True
    if not db.execute("""
       CREATE TABLE settings (
            id INTEGER PRIMARY KEY,
            current_season INTEGER NOT NULL
        )
    """):
        flash("Error creating table", "error")
        error = True
    if not db.execute("""
        CREATE TABLE pool (
            id INTEGER PRIMARY KEY,
            pool_name TEXT NOT NULL,
            pool_slug TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            num_picks INTEGER,
            pool_type TEXT,
            dollay_buy_in NUMERIC,
            season INTEGER NOT NULL
        )
    """):
        flash("Error creating table", "error")
        error = True
    if not db.execute("""
        CREATE TABLE contestant (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            image_path TEXT NOT NULL,
            left_show_in_episode INTEGER NOT NULL,
            season INTEGER NOT NULL
        )
    """):
        flash("Error creating table", "error")
        error = True
    if not db.execute("""
        CREATE TABLE user_pool_map (
            user_id INTEGER NOT NULL,
            pool_id INTEGER NOT NULL,
            is_admin BOOLEAN NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user(id),
            FOREIGN KEY (pool_id) REFERENCES pool(id)
        )
    """):
        flash("Error creating table", "error")
        error = True
    if not db.execute("""
        CREATE TABLE pick (
            user_id INTEGER NOT NULL,
            contestant_id INTEGER NOT NULL,
            FOREIGN KEY (user_id) REFERENCES user(id),
            FOREIGN KEY (contestant_id) REFERENCES contestant(id)
        )
    """):
        flash("Error creating table", "error")
        error = True

    if not error:
        flash("Tables successfully created")
    return redirect(url_for('index'))
    
@app.route("/test_admin", methods=["GET"])
def test_admin():
    password_hash = generate_password_hash("ZXasdqwe123")
    db.execute("INSERT INTO user (name, email, password_hash, is_site_admin) VALUES (?, ?, ?, ?)", "Peter", "peter.chinman@gmail.com", password_hash, 1)
    flash("Admin user successfully added", "message")
    return redirect(url_for('index'))

@app.route("/", methods=["GET"])
def index():
    if request.method == "GET":
        return render_template("index.html")

@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
     
    if request.method == "POST":
            contestant = request.form.get("contestant")
            in_week = request.form.get("in_week")

            if not contestant:
                return apology("You must include who was voted out", 400)
            if not in_week:
                return apology("You must include the week", 400)

            db.execute("UPDATE contestant SET left_show_in_episode = ? WHERE id = ?", in_week, contestant)

            return redirect(url_for('index'))

    if request.method == "GET":

        last_week = db.execute("SELECT MAX(left_show_in_episode) FROM contestant")[0]['MAX(left_show_in_episode)']

        if last_week:
            current_week = 1 + int(last_week)
        else:
            current_week = 1

        contestants = db.execute("SELECT * FROM contestant WHERE left_show_in_episode IS NULL")

        return render_template("admin.html", contestants=contestants, current_week=current_week)

@app.route("/login", methods=["GET", "POST"])
def login():

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure user_name was submitted
        email = request.form.get("email")
        password = request.form.get("password")

        if not email:
            return apology("must provide email", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        # Query database for email
        rows = db.execute(
            "SELECT * FROM user WHERE email = ?", email
        )

        # Ensure user_name exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["password_hash"], password
        ):
            return apology("invalid User Name and/or Password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # TODO will this work? is it bool or string?
        is_site_admin = rows[0]["is_site_admin"]
        if is_site_admin:
            session["is_site_admin"] = is_site_admin

        # if we came here from somewhere else, go back there
        # TODO why isn't this working??
        next_page = request.args.get('next')
        if next_page:
            return redirect(next_page)
        return redirect(url_for('index'))

    if request.method == "GET":
        return render_template("login.html")
    

@app.route("/user/<user_id>", methods=["GET", "POST"])
def user(user_id):

    # check user is correct

    if str(session["user_id"]) != user_id:
        flash("You do not have access to this page.", "error")
        return redirect(url_for('login')), 403
    

    
    if request.method == "GET":
        # get pools, is_admin from user
        pools = db.execute("SELECT pool_id, is_admin, pool_slug, pool_name, season FROM user_pool_map JOIN pool ON user_pool_map.pool_id = pool.id WHERE user_id = ?", user_id)
        user = db.execute("SELECT name, email FROM user WHERE id = ?", user_id)[0]
        
        return render_template("user.html", pools=pools, user=user)
    
    # TO DO update user info

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()
    flash("Logged out!")

    return redirect("/")

@app.route("/pool/create", methods=["GET", "POST"])
@login_required
def create():

    if request.method == "POST":
        pool_name = request.form.get("pool_name")
        password = request.form.get("password")
        confirmation = request.form.get("confimation")

        if not pool_name:
            return apology("You must include Pool Name", 400)
        if not password:
            return apology("You must include Password", 400)
        if not confirmation:
            return apology("You must include Confirmation", 400)

        
        # check and sanitize pool_name

        # convert pool_name to pool_slug
        pool_slug = slugify(pool_name)
        

        if not is_valid_subdirectory_name(pool_slug):
            return apology("Problem with pool name, please try again.", 400)
        # check if pool_slug already in admin (maybe not best place to do this, but it should work)
        sanitized_pool_slug = sanitize_subdirectory_name(pool_slug)
        if len(db.execute("SELECT pool_slug FROM pool WHERE pool_slug = ?", sanitized_pool_slug)) != 0:
            return apology("Pool Name already in use", 400)
        
        # check password & confirmation

        if password == confirmation:

            # hash password
            hash = generate_password_hash(password)
            # get current season
            current_season = db.execute("SELECT current_season FROM settings")[0]["current_season"]
            pool_id = db.execute("INSERT INTO pool (password_hash, pool_name, pool_slug, season) VALUES(?, ?, ?, ?)", hash, pool_name, sanitized_pool_slug, current_season)
            # insert into user_pool_map
            db.execute("INSERT INTO user_pool_map (user_id, pool_id) VALUES (?, ?)", session["user_id"], pool_id)
    
            


        # else: passwords don't match
        else:
            return apology("password and confirmation do not match", 400)
    
        # TODO is this the right re-direct? or separate <pool>/setup page? how to check if pool has been properly setup?
        return redirect(url_for('pool_admin', pool_slug = sanitized_pool_slug))

    if request.method == "GET":
        return render_template("pool/create.html")

ALLOWED_pool_slug_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
ALLOWED_USER_NAME_REGEX = re.compile(r'^[a-zA-Z0-9\._-]+$')

def is_valid_subdirectory_name(name):
    # Check if the name matches the allowed characters regex and has a reasonable length
    return bool(ALLOWED_pool_slug_REGEX.match(name)) and len(name) <= 50
# TODO I'll have to use this for create an account page
def is_valid_user_name(name):
    return bool(ALLOWED_USER_NAME_REGEX.match(name)) and len(name) <=50
def sanitize_subdirectory_name(name):
    sanitized_pool_slug = os.path.normpath(name)
    return sanitized_pool_slug




    

@app.route('/pool/<pool_slug>', methods=["GET"])
def show_pool(pool_slug):

    if request.method == "GET":
        
        # TODO password??
        # render template with pool login form?

        # get num_picks
        num_picks = db.execute("SELECT * FROM admin WHERE pool_slug IS ?", pool_slug)[0]["num_picks"]
        current_week = 1 + int(db.execute("SELECT MAX(left_show_in_episode) from survivors")[0]['MAX(left_show_in_episode)'])


        # First Get Rows of unique users from <pool_slug>
        
        rows = db.execute("""SELECT * FROM users
                                WHERE pool_id IS (SELECT id FROM admin WHERE pool_slug is ?)
                                ORDER BY user_id""", pool_slug)

        # Now iterate over rows getting users picks, left_show_in_episode, and points and adding them to each row-dict
        # formatted [{'pick0': [img path], 'left_show_in_episode0': [insert week pick0 voted out in] 'pick1' : ____, …, 'points' : user_total_points}]
        for row in rows:

            rows_of_picks = db.execute("""SELECT image_path, left_show_in_episode FROM survivors
                                            JOIN picks ON survivors.contestant_id = picks.contestant_id
                                            WHERE user_id IS ?
                                            ORDER BY left_show_in_episode""", row['user_id'])

            # now we iterate over each individual user's individual picks
            user_total_points = 0
            for j in range(len(rows_of_picks)):
                # rows_of_picks[j]['x'] x need to be the same as SELECT x from rows_of_picks
                # TODO: cool to have greyed out version of the images for survivors voted out
                row[f'pick{j}'] = rows_of_picks[j]['image_path']
                # below int conversion requires "or 0" in case of None
                # thus surivors who haven't been voted out, have value 0
                row[f'left_show_in_episode{j}'] = int(rows_of_picks[j]['left_show_in_episode'] or 0)
                # implement POINTS and add it to each row  
                weeks_survived = current_week if row[f'left_show_in_episode{j}'] == 0 else row[f'left_show_in_episode{j}']
                # TODO: figure out best value for 2, should store this alongside pool_slug and type
                # 2 is prob too strong. 
                user_total_points += 2**(weeks_survived - 1)
            row['points'] = user_total_points 


        rows = sorted(rows, key=lambda x: x['points'], reverse=True)


        return render_template("pool/pool_slug.html", num_picks=num_picks, current_week=current_week, rows=rows, pool_slug=pool_slug)

# TODO this should maybe be a list of dicts with keys as html name and values as html dispay?
pool_types = ['points', 'sole survivor']

@app.route('/pool/<pool_slug>/admin', methods=["GET", "POST"])
def pool_admin(pool_slug):
    # TODO: set up password protect for this page? simple as throwing in login decoration?
    if request.method == "GET":
        row = db.execute("SELECT * FROM admin WHERE pool_slug IS ?", pool_slug)[0]
        return render_template("pool/admin.html", pool_types=pool_types, row=row, pool_slug=pool_slug)

    if request.method == "POST":
        pool_password = request.form.get("pool_password")
        pool_type = request.form.get("pool_type")
        pool_dollar = int(request.form.get("pool_dollar"))
        num_picks = int(request.form.get("num_picks"))

        if not pool_password:
            return apology("Pool Password required", 400)
        if pool_type not in pool_types:
            return apology("Incorrect pool type", 400)
        if pool_dollar < 0:
            return apology("Pool dollar amount can not be negative", 400)
        if not num_picks:
            return apology("Must choose number of Survivor picks", 400)
        if num_picks <=0 or num_picks >=18:
            return apology("Invalid number of Survivor picks", 400)

        db.execute("""UPDATE admin
                      SET pool_password = ?,
                      pool_type = ?,
                      pool_dollar = ?,
                      num_picks = ?
                      WHERE pool_slug is ?"""
                    , pool_password, pool_type, pool_dollar, num_picks, pool_slug)
        
        return redirect(url_for('pool_admin', pool_slug=pool_slug))
        
@app.route('/pool/<pool_slug>/signup', methods=["GET", "POST"])
def pool_signup(pool_slug):
    if request.method == "GET":

        #implement pool password

        # check pool_slug
        pool_slug_check = db.execute("SELECT * FROM admin WHERE pool_slug IS ?", pool_slug)
        if len(pool_slug_check) != 1:
            return apology("Not a valid Pool Name", 400)

        # get list of survivors
        survivors = db.execute("SELECT * FROM survivors")

        # get num_picks TODO should all pool settings be in separate POOL table?

        num_picks = pool_slug_check[0]["num_picks"]
        
        return render_template("pool/signup.html", pool_slug=pool_slug, survivors=survivors, num_picks=num_picks)

    if request.method == "POST":
        
        user_name = request.form.get("user_name")
        picks = request.form.getlist("checkboxes")

        num_picks = db.execute("SELECT * FROM admin WHERE pool_slug IS ?", pool_slug)[0]["num_picks"]

        #check user_name and number of picks
        if not user_name:
            return apology("You must enter a user_name", 400)
        if len(db.execute("""SELECT * FROM users WHERE user_name IS ? 
                        AND pool_id is (SELECT id FROM admin WHERE pool_slug IS ?)""",
                        user_name, pool_slug)) > 0:
            return apology ("That user_name is already in use in your pool", 400)
        if len(picks) != num_picks:
            return apology("Wrong number of contestants selected", 400)

        #update users and picks databases
        
        db.execute("""INSERT INTO users (user_name, pool_id) 
                        VALUES (?,
                               (SELECT id FROM admin WHERE pool_slug IS ?))""",
                        user_name, pool_slug)

        for pick in picks:
            db.execute("""INSERT INTO picks (user_id, contestant_id)
                        VALUES ((SELECT user_id FROM users WHERE user_name is ?),
                                ?)""", 
                        user_name, int(pick))

        # actually: no reason to update the session with this
        # session["pool_user_id"] = db.execute("SELECT * FROM users WHERE user_name IS ?", user_name)[0]["user_id"]

        return redirect(url_for('show_pool', pool_slug=pool_slug))
        
    