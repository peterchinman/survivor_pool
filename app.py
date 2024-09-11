import os
import re

from cs50 import SQL
from datetime import datetime
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required

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

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":

            goodbye = db.execute("SELECT * FROM survivors ORDER BY voted_out_in_week DESC LIMIT 1")

            return render_template("index.html", goodbye=goodbye)

@app.route("/admin", methods=["GET", "POST"])
@login_required()
def admin():
    if request.method == "POST":
            voted_out = request.form.get("voted_out")
            in_week = request.form.get("in_week")

            if not voted_out:
                return apology("You must include who was voted out", 400)
            if not in_week:
                return apology("You must include the week", 400)

            db.execute("UPDATE survivors SET voted_out_in_week = ? WHERE contestant_id = ?", in_week, voted_out)

            return redirect(url_for('index'))

    if request.method == "GET":

        # set up password protect!!

        current_week = 1 + int(db.execute("SELECT MAX(voted_out_in_week) from survivors")[0]['MAX(voted_out_in_week)'])
        survivors = db.execute("SELECT * FROM survivors WHERE voted_out_in_week IS NULL")

        return render_template("admin.html", survivors=survivors, current_week=current_week)

#login is used for getting into /pool/<pool>/admin
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM admin WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to their pool admin page
        # TO DO this should have the pool slug in it
        return redirect("/pool/admin")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()
    flash("Logged out!")

    # Redirect user to login form
    return redirect("/")

@app.route("/pool/create", methods=["GET", "POST"])
@login_required
def create():

    if request.method == "POST":
        pool_name = request.form.get("pool_name")
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confimation")

        if not pool_name:
            return apology("You must include Pool Name", 400)
        if not username:
            return apology("You must include User Name", 400)
        if not password:
            return apology("You must include Password", 400)
        if not confirmation:
            return apology("You must include Confirmation", 400)

        
        # check and sanitize pool_name

        if not is_valid_subdirectory_name(pool_name):
            return apology("Pool Name can only have letters, numbers, underscores, and dashes.", 400)
        # also check if pool_name already in admin (maybe not best place to do this, but it should work)
        sanitized_pool_name = sanitize_subdirectory_name(pool_name)
        if len(db.execute("SELECT pool_name FROM admin WHERE pool_name = ?", sanitized_pool_name)) != 0:
            return apology("Pool Name already in use", 400)

        # check user_name

        if not is_valid_user_name(username):
            return apology("User Name can only have letters, numbers, underscores, dashes, and periods.", 400)
        
        # check password & confirmation

        if password == confirmation:

            #check name already in admin, return apology, if not hash password and send to database

            if len(db.execute("SELECT username FROM admin WHERE username = ?", username)) != 0:
                return apology("User Name already in use", 400)
            
            else:
                hash = generate_password_hash(password)
                db.execute("INSERT INTO admin (username, hash, pool_name) VALUES(?, ?, ?)", username, hash, sanitized_pool_name)
                


        # else: passwords don't match
        else:
            return apology("password and confirmation do not match", 400)
        
        #update session with user_id, pool_name

        rows = db.execute("SELECT * FROM admin WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]
        session["pool_name"] = rows[0]["pool_name"]
        
        return redirect(url_for('pool_admin', pool_name = session["pool_name"]))

    if request.method == "GET":
        return render_template("pool/create.html")

    """Get stock quote."""

ALLOWED_POOL_NAME_REGEX = re.compile(r'^[a-zA-Z0-9_-]+$')
ALLOWED_USER_NAME_REGEX = re.compile(r'^[a-zA-Z0-9\._-]+$')

def is_valid_subdirectory_name(name):
    # Check if the name matches the allowed characters regex and has a reasonable length
    return bool(ALLOWED_POOL_NAME_REGEX.match(name)) and len(name) <= 50
def is_valid_user_name(name):
    return bool(ALLOWED_USER_NAME_REGEX.match(name)) and len(name) <=50
def sanitize_subdirectory_name(name):
    sanitized_pool_name = os.path.normpath(name)
    return sanitized_pool_name

@app.route('/pool/<pool_name>', methods=["GET"])
def show_pool(pool_name):

    if request.method == "GET":
        
        # TODO password??
        # render template with pool login form?

        # get num_picks
        num_picks = db.execute("SELECT * FROM admin WHERE pool_name IS ?", pool_name)[0]["num_picks"]
        current_week = 1 + int(db.execute("SELECT MAX(voted_out_in_week) from survivors")[0]['MAX(voted_out_in_week)'])


        # First Get Rows of unique users from <pool_name>
        
        rows = db.execute("""SELECT * FROM users
                                WHERE pool_id IS (SELECT id FROM admin WHERE pool_name is ?)
                                ORDER BY user_id""", pool_name)

        # Now iterate over rows getting users picks, voted_out_in_week, and points and adding them to each row-dict
        # formatted [{'pick0': [img path], 'voted_out_in_week0': [insert week pick0 voted out in] 'pick1' : ____, …, 'points' : user_total_points}]
        for row in rows:

            rows_of_picks = db.execute("""SELECT image_path, voted_out_in_week FROM survivors
                                            JOIN picks ON survivors.contestant_id = picks.contestant_id
                                            WHERE user_id IS ?
                                            ORDER BY voted_out_in_week""", row['user_id'])

            # now we iterate over each individual user's individual picks
            user_total_points = 0
            for j in range(len(rows_of_picks)):
                # rows_of_picks[j]['x'] x need to be the same as SELECT x from rows_of_picks
                # TODO: cool to have greyed out version of the images for survivors voted out
                row[f'pick{j}'] = rows_of_picks[j]['image_path']
                # below int conversion requires "or 0" in case of None
                # thus surivors who haven't been voted out, have value 0
                row[f'voted_out_in_week{j}'] = int(rows_of_picks[j]['voted_out_in_week'] or 0)
                # implement POINTS and add it to each row  
                weeks_survived = current_week if row[f'voted_out_in_week{j}'] == 0 else row[f'voted_out_in_week{j}']
                # TODO: figure out best value for 2, should store this alongside pool_name and type
                # 2 is prob too strong. 
                user_total_points += 2**(weeks_survived - 1)
            row['points'] = user_total_points 


        rows = sorted(rows, key=lambda x: x['points'], reverse=True)


        return render_template("pool/pool_name.html", num_picks=num_picks, current_week=current_week, rows=rows, pool_name=pool_name)

# TODO this should maybe be a list of dicts with keys as html name and values as html dispay?
pool_types = ['points', 'sole survivor']

@app.route('/pool/<pool_name>/admin', methods=["GET", "POST"])
def pool_admin(pool_name):
    # TODO: set up password protect for this page? simple as throwing in login decoration?
    if request.method == "GET":
        row = db.execute("SELECT * FROM admin WHERE pool_name IS ?", pool_name)[0]
        return render_template("pool/admin.html", pool_types=pool_types, row=row, pool_name=pool_name)

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
                      WHERE pool_name is ?"""
                    , pool_password, pool_type, pool_dollar, num_picks, pool_name)
        
        return redirect(url_for('pool_admin', pool_name=pool_name))
        
@app.route('/pool/<pool_name>/signup', methods=["GET", "POST"])
def pool_signup(pool_name):
    if request.method == "GET":

        #implement pool password

        # check pool_name
        pool_name_check = db.execute("SELECT * FROM admin WHERE pool_name IS ?", pool_name)
        if len(pool_name_check) != 1:
            return apology("Not a valid Pool Name", 400)

        # get list of survivors
        survivors = db.execute("SELECT * FROM survivors")

        # get num_picks TODO should all pool settings be in separate POOL table?

        num_picks = pool_name_check[0]["num_picks"]
        
        return render_template("pool/signup.html", pool_name=pool_name, survivors=survivors, num_picks=num_picks)

    if request.method == "POST":
        
        username = request.form.get("username")
        picks = request.form.getlist("checkboxes")

        num_picks = db.execute("SELECT * FROM admin WHERE pool_name IS ?", pool_name)[0]["num_picks"]

        #check username and number of picks
        if not username:
            return apology("You must enter a username", 400)
        if len(db.execute("""SELECT * FROM users WHERE username IS ? 
                        AND pool_id is (SELECT id FROM admin WHERE pool_name IS ?)""",
                        username, pool_name)) > 0:
            return apology ("That username is already in use in your pool", 400)
        if len(picks) != num_picks:
            return apology("Wrong number of contestants selected", 400)

        #update users and picks databases
        
        db.execute("""INSERT INTO users (username, pool_id) 
                        VALUES (?,
                               (SELECT id FROM admin WHERE pool_name IS ?))""",
                        username, pool_name)

        for pick in picks:
            db.execute("""INSERT INTO picks (user_id, contestant_id)
                        VALUES ((SELECT user_id FROM users WHERE username is ?),
                                ?)""", 
                        username, int(pick))

        # actually: no reason to update the session with this
        # session["pool_user_id"] = db.execute("SELECT * FROM users WHERE username IS ?", username)[0]["user_id"]

        return redirect(url_for('show_pool', pool_name=pool_name))
        
    