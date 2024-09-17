import os
import re

from cs50 import SQL
from datetime import datetime, timedelta
from flask import Flask, flash, make_response, redirect, render_template, request, session, url_for
from flask_session import Session
from markupsafe import escape
from slugify import slugify
from urllib.parse import urlparse
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required, admin_required

# WIDEFRAME TODO:
#   - Use SQLAlchemy
#   - Use a config.py file
#   - Consider blueprints
#   - More robust error handling
#       - Pass form errors back to form, consult HTMX
#   - Get HTMX set up  

# Configure application
app = Flask(__name__)
app.secret_key = 'c0f9c9533444660bd9686d841d59c4a6fe3dc8b849fc03da8647587bd3e2681a'
app.config['TEMPLATES_AUTO_RELOAD'] = True # turn off for production
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0 # set higher for production
if (__name__ == "__main__"):
    app.run(debug=True)

# Configure session to use filesystem (instead of signed cookies)

app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
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
                return apology("You must include who was voted out", 422)
            if not in_week:
                return apology("You must include the week", 422)

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
        print(next_page)
        if next_page:
            return redirect(url_for(next_page))
        return redirect(url_for('index'))

    if request.method == "GET":
        return render_template("login.html")
    
@app.route("/create-account", methods=["GET", "POST"])
def create_account():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        is_site_admin = 0

        if not name:
            return apology("You must include a Name", 422)
        if len(name) > 20:
            return apology("Name must 20 characters or less", 422)
        if len(name) < 2:
            return apology("Name must be at least two characters", 422)
        name = escape(name)
        
        if not email:
            return apology("You must include an email address", 422)
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        if not re.match(email_regex, email):
            return apology("Invalid email address", 422)
        if len(email) > 254:
            return apology("Email address too long", 422)
        
        if not password:
            return apology("You must include a password", 422)
        if not confirmation:
            return apology("You must include a password confirmation", 422)
        
        #check if email address already used
        if len(db.execute("SELECT email FROM user WHERE email = ?", email)) != 0:
            return apology("Email address already in use!", 422)
        
        # check password & hash

        if password == confirmation:
            password_hash = generate_password_hash(password)
            user_id = db.execute("INSERT INTO user (name, email, password_hash, is_site_admin) VALUES (?, ?, ?, ?)", name, email, password_hash, 0)
            if user_id:
                flash("User successfully added!", "message")
                session["user_id"] = user_id
                # TODO set up this redirect to get us back to page we wanted to be at
                return redirect(url_for('user', user_id=user_id))
            else:
                flash("Error adding user to database!", "error")
                
        



    if request.method == "GET":
        return render_template("create-account.html")
    

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

 # TODO this should maybe be a list of dicts with keys as html name and values as html dispay?
pool_types = {
    "points" : {
        "name" : "points",
        "display" : "Points",
        "description" : "Whoever has the most points in the end wins. Each survivor starts with 1 point. Each episode they survive their point value is multiplied by the points multiplier.",
    },
    "sole survivor" : {
        "name" : "sole survivor",
        "display" : "Sole Survivor",
        "description" : "Whoever chooses the sole survivor wins. If no one picks the sole survivor, or in the event of the tie, whoever chooses the survivor to survive the longest wins."
    }
}

@app.route("/pool/create", methods=["GET", "POST"])
@login_required
def create_pool():

    if request.method == "POST":

        # TODO: a user should only be able to be admin for one pool each season!

        pool_name = request.form.get("pool_name")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        pool_type = request.form.get("pool_type")
        multiplier = request.form.get("multiplier")
        num_picks = int(request.form.get("num_picks"))
        dollar_buy_in = int(request.form.get("dollar_buy_in"))
        payout_places = request.form.get("payout_places")

        percentage_dict = {}

        for key, value in request.args.items():
            if key.startswith('place-'):
                place_number = int(key.split('-')[1])
                percentage_dict[place_number] = value

        
        if not pool_name:
            return apology("You must include Pool Name", 422)
        if not password:
            return apology("You must include Password", 422)
        if not confirmation:
            return apology("You must include Confirmation", 422)
        if not pool_type:
            return apology("Choose a pool type", 422)
        if pool_type not in pool_types:
            return apology("Incorrect pool type", 422)
        if pool_type == 'points' and not 1 <= multiplier <= 5:
            return apology("Incorrect multiplier", 422)
        if not num_picks:
            return apology("Must choose number of Survivor picks", 422)
        if num_picks <=0 or num_picks >=18:
            return apology("Invalid number of Survivor picks", 422)
        if dollar_buy_in < 0:
            return apology("Pool dollar amount can not be negative", 422)
        if payout_places < 1 or payout_places > 10:
            return apology("Payout places must be between 1 and 10", 422)
        if len(percentage_dict) != payout_places:
            return apology("Mismatch between number of payout_places and percentages listed", 422)
        
        total_percentage = 0
        for key, value in percentage_dict.items():
            try:
                total_percentage += float(value)
            except ValueError:
                pass
        
        if total_percentage != 100:
            return apology("Percentages must add up to 100%", 422)

        
        # check and sanitize pool_name

        # convert pool_name to pool_slug
        pool_slug = slugify(pool_name)

        if not is_valid_subdirectory_name(pool_slug):
            return apology("Problem with pool name, please try again.", 422)
        
        # check if pool_slug already in admin
        sanitized_pool_slug = sanitize_subdirectory_name(pool_slug)
        if len(db.execute("SELECT pool_slug FROM pool WHERE pool_slug = ?", sanitized_pool_slug)) != 0:
            return apology("Pool Name already in use", 422)
        
        # check password & confirmation

        if password == confirmation:

            # hash password
            hash = generate_password_hash(password)
            # get current season
            # implemented this if else workaround for testing
            row = db.execute("SELECT current_season FROM settings")
            if row:
                current_season = row[0]["current_season"]
            else:
                current_season = 1
            # insert into pool
            pool_id = db.execute("INSERT INTO pool (password_hash, pool_name, pool_slug, season, num_picks, pool_type, dollar_buy_in) VALUES(?, ?, ?, ?, ?, ?, ?)", hash, pool_name, sanitized_pool_slug, current_season, num_picks, pool_type, dollar_buy_in)
            # insert into user_pool_map
            db.execute("INSERT INTO user_pool_map (user_id, pool_id, is_admin) VALUES (?, ?, ?)", session["user_id"], pool_id, 1)
    
            


        # else: passwords don't match
        else:
            return apology("password and confirmation do not match", 422)
    
        # TODO is this the right re-direct? or separate <pool>/setup page? how to check if pool has been properly setup?
        return redirect(url_for('pool_admin', pool_slug = sanitized_pool_slug))

    if request.method == "GET":
        return render_template("pool/create.html", pool_types=pool_types)
    
@app.route('/check-pool-type', methods=["GET"])
def check_pool_type():
    pool_type = request.args.get("pool_type")
    print(f"Received pool_type: {pool_type}")  # Debugging log
    if pool_type == "points":
        return render_template("pool/multiplier_field.html")
    else:
        return ""  # Return nothing if the pool type is not "points"

@app.route('/payout-places', methods=["GET"])
def payout_places():
    payout_places = request.args.get("payout-places", type=int)

    percentage_dict = {}

    for key, value in request.args.items():
         if key.startswith('place-'):
            place_number = int(key.split('-')[1])
            percentage_dict[place_number] = value
             
    response = make_response(render_template("pool/payout-percentages.html", payout_places=payout_places, percentage_dict=percentage_dict)) 
    response.headers['HX-Trigger-After-Settle'] = 'payout-places-updated'
    return response

@app.route('/calculate-percentages', methods=['GET'])
def calculate_percentages():
    total_percentage = 0
    for key, value in request.args.items():
         if key.startswith('place-'):
            try:
                total_percentage += float(value)
            except ValueError:
                pass  # Ignore non-numeric inputs
    
    remaining_percentage = 100 - total_percentage
    
    return render_template('pool/percentage-summary.html', 
                           total_percentage=total_percentage,
                           remaining_percentage=remaining_percentage)

# TODO these probably shouldn't be floating in the global

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
        num_picks = db.execute("SELECT * FROM pool WHERE pool_slug IS ?", pool_slug)[0]["num_picks"]
        current_week = 1 + int(db.execute("SELECT MAX(left_show_in_episode) from survivors")[0]['MAX(left_show_in_episode)'])


        # First Get Rows of unique users from <pool_slug>
        
        rows = db.execute("""SELECT * FROM user_pool_map
                                JOIN user
                                ON user_pool_map.user_id = user.id
                                WHERE pool_id IS (SELECT id FROM pool WHERE pool_slug is ?)
                                ORDER BY user_id""", pool_slug)

        # Now iterate over rows getting users picks, left_show_in_episode, and points and adding them to each row-dict
        # formatted [{'pick0': [img path], 'left_show_in_episode0': [insert week pick0 voted out in] 'pick1' : ____, …, 'points' : user_total_points}]
        for row in rows:

            rows_of_picks = db.execute("""SELECT image_path, left_show_in_episode, name 
                                            FROM contestant
                                            JOIN pick ON contestant.id = pick.contestant_id
                                            WHERE user_id IS ?
                                            ORDER BY left_show_in_episode""", row['user_id'])

            # now we iterate over each individual user's individual picks
            user_total_points = 0
            for j in range(len(rows_of_picks)):
                # rows_of_picks[j]['x'] x need to be the same as SELECT x from rows_of_picks
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





@app.route('/pool/<pool_slug>/admin', methods=["GET", "POST"])
@login_required
def pool_admin(pool_slug):
    # TODO: set up password protect for this page? simple as throwing in login decoration?

    is_admin_row = db.execute("SELECT is_admin FROM user_pool_map WHERE user_id = ? AND pool_id = (SELECT id FROM pool WHERE pool_slug = ?)", session["user_id"], pool_slug)
    if is_admin_row:
        is_admin = is_admin_row[0]["is_admin"]
    else:
        is_admin = None
    if not is_admin:
        flash("You are not authorized to access this page.", "warning")
        return redirect(url_for('index')), 403

    if request.method == "GET":

       

        row = db.execute("SELECT * FROM pool WHERE pool_slug IS ?", pool_slug)[0]
        return render_template("pool/admin.html", pool_types=pool_types, row=row, pool_slug=pool_slug)

    if request.method == "POST":
        pool_password = request.form.get("pool_password")
        pool_type = request.form.get("pool_type")
        pool_dollar = int(request.form.get("pool_dollar"))
        num_picks = int(request.form.get("num_picks"))

        password_hash = generate_password_hash(pool_password)

        if not pool_password:
            return apology("Pool Password required", 422)
        if pool_type not in pool_types:
            return apology("Incorrect pool type", 422)
        if pool_dollar < 0:
            return apology("Pool dollar amount can not be negative", 422)
        if not num_picks:
            return apology("Must choose number of Survivor picks", 422)
        if num_picks <=0 or num_picks >=18:
            return apology("Invalid number of Survivor picks", 422)

        db.execute("""UPDATE pool
                      SET password_hash = ?,
                      pool_type = ?,
                      dollar_buy_in = ?,
                      num_picks = ?
                      WHERE pool_slug is ?"""
                    , password_hash, pool_type, pool_dollar, num_picks, pool_slug)
        
        return redirect(url_for('show_pool', pool_slug=pool_slug))
        
@app.route('/pool/<pool_slug>/signup', methods=["GET", "POST"])
def pool_signup(pool_slug):
    if request.method == "GET":

        # TODO implement pool password

        # check pool_slug
        # TODO is this necessary? 
        pool_slug_check = db.execute("SELECT * FROM pool WHERE pool_slug IS ?", pool_slug)
        if len(pool_slug_check) != 1:
            return apology("Not a valid Pool", 422)

        # get list of survivors
        contestants = db.execute("SELECT * FROM contestants")

        # get num_picks

        num_picks = pool_slug_check[0]["num_picks"]
        
        return render_template("pool/signup.html", pool_slug=pool_slug, contestants=contestants, num_picks=num_picks)

    if request.method == "POST":
        
        # TODO get user somehow
        user_name = request.form.get("user_name")
        picks = request.form.getlist("checkboxes")

        num_picks = db.execute("SELECT * FROM admin WHERE pool_slug IS ?", pool_slug)[0]["num_picks"]

        #check number of picks TODO implement client side verification
        if len(picks) != num_picks:
            return apology("Wrong number of contestants selected", 422)

        # TODO make these work with the current system
        # update users and picks databases
        
        db.execute("""INSERT INTO users (user_name, pool_id) 
                        VALUES (?,
                               (SELECT id FROM admin WHERE pool_slug IS ?))""",
                        user_name, pool_slug)

        for pick in picks:
            db.execute("""INSERT INTO picks (user_id, contestant_id)
                        VALUES ((SELECT user_id FROM users WHERE user_name is ?),
                                ?)""", 
                        user_name, int(pick))

        return redirect(url_for('show_pool', pool_slug=pool_slug))
        
    