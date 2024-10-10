import os
import re
import json
import secrets


from cs50 import SQL
from datetime import datetime, timedelta
from flask import Flask, flash, make_response, redirect, render_template, request, session, url_for
from flask_session import Session
from markupsafe import escape
from slugify import slugify
from urllib.parse import urlparse
from werkzeug.security import check_password_hash, generate_password_hash


from helpers import apology, login_required, site_admin_required, pool_admin_required

# LONGTERM TODO:
#   - Use SQLAlchemy
#   - Use a config.py file
#   - Consider blueprints
#   - More robust error handling
#       - Pass form errors back to form, consult HTMX 

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


@app.route("/init-db", methods=["GET"])
def init_db():
    #create tables
    error = False
    if not db.execute("""
        CREATE TABLE user (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT,
            password_hash TEXT,
            is_site_admin BOOLEAN
        )
    """):
        error = True
    if not db.execute("""
       CREATE TABLE settings (
            id INTEGER PRIMARY KEY,
            current_season INTEGER NOT NULL
        )
    """):
        error = True
    if not db.execute("""
        CREATE TABLE pool (
            id INTEGER PRIMARY KEY,
            pool_name TEXT NOT NULL,
            pool_slug TEXT NOT NULL,
            pool_type TEXT NOT NULL,
            multiplier NUMERIC,
            num_picks INTEGER NOT NULL,
            dollar_buy_in NUMERIC,
            payout_places INTEGER,
            payout_json TEXT,
            season INTEGER NOT NULL
        )
    """):
        error = True
    if not db.execute("""
        CREATE TABLE contestant (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            image_path TEXT NOT NULL,
            left_show_in_episode INTEGER,
            season INTEGER NOT NULL
        )
    """):
        error = True

    if not db.execute("""
        CREATE TABLE user_pool_map (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            pool_id INTEGER NOT NULL,
            is_admin BOOLEAN,
            FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
            FOREIGN KEY (pool_id) REFERENCES pool(id) ON DELETE CASCADE,
            UNIQUE (user_id, pool_id)
                      
        )
    """):
        error = True
    if not db.execute("""
        CREATE TABLE pick (
            user_pool_map_id INTEGER NOT NULL,
            contestant_id INTEGER NOT NULL,
            FOREIGN KEY (user_pool_map_id) REFERENCES user_pool_map(id) ON DELETE CASCADE,
            FOREIGN KEY (contestant_id) REFERENCES contestant(id) ON DELETE CASCADE,
            UNIQUE (user_pool_map_id, contestant_id)
        )
    """):
        error = True
    if not db.execute("""
        CREATE TABLE invite_token(
            id INTEGER PRIMARY KEY,
            pool_id INTEGER NOT NULL,
            token TEXT NOT NULL,
            active BOOLEAN NOT NULL,
            FOREIGN KEY (pool_id) REFERENCES pool(id) ON DELETE CASCADE
        )
    """):
        error = True

    if error:
        flash("Error creating tables", "error")
    else:
        flash("Tables successfully created", "message")
    return redirect(url_for('index'))
    
@app.route("/init-admin", methods=["GET"])
def init_admin():
    password_hash = generate_password_hash("test")
    user_id = db.execute("INSERT INTO user (name, email, password_hash, is_site_admin) VALUES (?, ?, ?, ?)", "Peter", "test@test.com", password_hash, 1)
    session["user_id"] = user_id
    session["user_name"] = "Peter"
    session["is_site_admin"] = True
    flash("Admin user successfully added.", "message")
    return redirect(url_for('index'))

@app.route("/init-contestants", methods=["GET"])
def init_contestants():
    # Folder path containing the images
    folder_path = 'static/contestant-images/season-47'

    # Get a list of filenames without extensions
    names = [os.path.splitext(filename)[0] for filename in os.listdir(folder_path) if filename.endswith(('.webp'))]

    for name in names:
        if db.execute("INSERT INTO contestant (name, image_path, left_show_in_episode, season) VALUES (?, ?, NULL, ?)", name.capitalize(), "static/contestant-images/season-47/" + name + ".webp", 47):
            flash(name + " successfully added.", "message")
        else:
            flash("COULD NOT ADD" + name, "error")

    if db.execute("INSERT INTO settings (current_season) VALUES (47)"):
        flash("Set season to 47.", "message")
    else:
        flash("Error setting season.", "error")
    return redirect(url_for('index'))
    


@app.route("/", methods=["GET"])
def index():
    if request.method == "GET":
        return render_template("index.html")

@app.route("/admin", methods=["GET", "POST"])
@site_admin_required
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
            return apology("invalid email and/or Password", 403)
        
       

        # Get pools that a user is associated with

        # Uses: for pool_id in session["pools"].keys():
        #       if pool_id in session["pools"]:
        #       is_admin_status = session["pools"][1]["is_admin"]

        pools = db.execute("SELECT pool_id, pool_name, pool_slug, is_admin FROM user_pool_map JOIN pool ON user_pool_map.pool_id = pool.id WHERE user_id = ?", rows[0]["id"])

        session["pools"] = {pool["pool_id"] : {"is_admin" : pool.get("is_admin", 0), "pool_name": pool["pool_name"], "pool_slug": pool["pool_slug"]} for pool in pools}    

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["user_name"] = rows[0]["name"]

        is_site_admin = rows[0]["is_site_admin"]
        if is_site_admin:
            session["is_site_admin"] = is_site_admin

        next_page = request.args.get('next')
        if next_page:
            return redirect(url_for(next_page))
        else:
            return redirect(url_for('index'))

    if request.method == "GET":
        next = request.args.get('next')
        return render_template("login.html", next=next)
    
@app.route("/create-account", methods=["GET", "POST"])
def create_account():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        checkbox = request.form.get("checkbox")
        is_site_admin = 0

        # honeypot
        if checkbox:
            return redirect(url_for('index'))
        

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
                session["user_name"] = name
                

                next_page = request.args.get('next')
                if next_page:
                    return redirect(url_for(next_page))
                else:
                    return redirect(url_for('index'))
                
            else:
                flash("Error adding user to database!", "error")
                return redirect(url_for('index'))


    if request.method == "GET":
        return render_template("create-account.html")
    

@app.route("/user/<user_id>", methods=["GET", "POST"])
def user(user_id):

    # check user is correct

    if str(session.get("user_id")) != user_id:
        flash("You do not have access to this page.", "error")
        return redirect(url_for('login'))
    
    if request.method == "GET":
        # get pools, is_admin from user
        pools = db.execute("""
            SELECT pool_id, is_admin, pool_slug, pool_name, season
            FROM user_pool_map
            JOIN pool ON user_pool_map.pool_id = pool.id
            WHERE user_id = ?
            ORDER BY season DESC""", user_id)

        user = db.execute("SELECT name, email FROM user WHERE id = ?", user_id)[0]
        
        return render_template("user.html", pools=pools, user=user)
    
    # TO DO update user info

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()
    flash("Logged out!", "message")

    return redirect("/")

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

        pool_name = request.form.get("pool_name")
        # password = request.form.get("password")
        # confirmation = request.form.get("confirmation")
        pool_type = request.form.get("pool_type")
        multiplier = int(request.form.get("multiplier", 0))
        num_picks = int(request.form.get("num_picks"))
        dollar_buy_in = int(request.form.get("dollar_buy_in", 0))
        payout_places = int(request.form.get("payout_places", 0))

        payout_dict = {}
        total_percentage = 0

        for key, value in request.form.items():
            if key.startswith('place-'):
                place_number = int(key.split('-')[1])
                payout_dict[place_number] = value
                try:
                    total_percentage += float(value)
                except ValueError:
                    pass
        
        if payout_dict and total_percentage != 100:
            return apology("Percentages must add up to 100%", 422)

        payout_json = json.dumps(payout_dict)

        
        if not pool_name:
            return apology("You must include Pool Name", 422)
        if len(pool_name) < 2 or len(pool_name) > 20:
            flash("Pool Name must be between 2 and 20 characters", "error")
            return redirect(url_for('create_pool'))
        # if not password:
        #     return apology("You must include Password", 422)
        # if not confirmation:
        #     return apology("You must include Confirmation", 422)
        if not pool_type:
            return apology("Choose a pool type", 422)
        if pool_type not in pool_types:
            return apology("Incorrect pool type", 422)
        if pool_type == 'points' and not multiplier:
            return apology("Multiplier required", 422)
        if pool_type == 'points' and not 1 <= multiplier <= 5:
            return apology("Multiplier must be between 1 and 5", 422)
        if not num_picks:
            return apology("Must choose number of Survivor picks", 422)
        if num_picks <=0 or num_picks >=18:
            return apology("Invalid number of Survivor picks", 422)
        if dollar_buy_in < 0:
            return apology("Pool dollar amount can not be negative", 422)
        if payout_places < 0 or payout_places > 10:
            return apology("Payout places must be between 1 and 10", 422)
        if len(payout_dict) != payout_places:
            return apology("Mismatch between number of payout_places and percentages listed", 422)

        
        # check and sanitize pool_name

        # escape and slugify
        pool_name = escape(pool_name)
        pool_slug = slugify(pool_name)

        if not is_valid_subdirectory_name(pool_slug):
            return apology("Problem with pool name, please try again.", 422)
        
        # check if pool_slug already in admin
        sanitized_pool_slug = sanitize_subdirectory_name(pool_slug)
        if len(db.execute("SELECT pool_slug FROM pool WHERE pool_slug = ?", sanitized_pool_slug)) != 0:
            return apology("Pool Name already in use", 422)
        
        # check password & confirmation

        # if password == confirmation:

        #     # hash password
        #     password_hash = generate_password_hash(password)
        # get current season
        # implemented this if else workaround for testing
        row = db.execute("SELECT current_season FROM settings")
        if row:
            season = row[0]["current_season"]
        else:
            season = 0

        # insert into pool

        pool_id = db.execute("INSERT INTO pool (pool_name, pool_slug, pool_type, multiplier, num_picks, dollar_buy_in, payout_places, payout_json, season) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)", pool_name, sanitized_pool_slug, pool_type, multiplier, num_picks, dollar_buy_in, payout_places, payout_json, season)

        # insert into user_pool_map with is_admin set to true
        db.execute("INSERT INTO user_pool_map (user_id, pool_id, is_admin) VALUES (?, ?, ?)", session["user_id"], pool_id, 1)

        #create a invite token

        token = secrets.token_urlsafe(32)

        token_id = db.execute("INSERT INTO invite_token (pool_id, token, active) VALUES (?, ?, ?)", pool_id, token, 1)

        # update session
        if "pools" not in session:
            session["pools"] = {}

        session["pools"][pool_id] = {"is_admin": True, "pool_name": pool_name, "pool_slug": sanitized_pool_slug}


        flash("Pool successfully created", "message")
        return redirect(url_for('pool_admin', pool_slug=sanitized_pool_slug))
    
            


        # else: passwords don't match
        # else:
            # return apology("password and confirmation do not match", 422)
    
        

    if request.method == "GET":
        return render_template("pool/create.html", pool_types=pool_types)
    
@app.route('/check-pool-type', methods=["GET"])
def check_pool_type():
    pool_type = request.args.get("pool_type")
    if pool_type == "points":
        return render_template("pool/multiplier_field.html")
    else:
        return ""  # Return nothing if the pool type is not "points"

@app.route('/dollar_buy_in', methods=["GET"])
def dollar_buy_in():
    dollar_buy_in = request.args.get("dollar_buy_in")
    if dollar_buy_in:
        return render_template("pool/payouts.html")


@app.route('/payout-places', methods=["GET"])
def payout_places():
    payout_places = request.args.get("payout_places", type=int)

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
def sanitize_subdirectory_name(name):
    sanitized_pool_slug = os.path.normpath(name)
    return sanitized_pool_slug

@app.route('/pool/search', methods=["GET"])
def pool_search():
    pool_search = request.args.get("pool-search")
    if pool_search:
        pools = db.execute("SELECT pool_name, pool_slug FROM pool WHERE pool_name LIKE ?", ('%' + pool_search + '%'))
        return render_template("pool/search.html", pools=pools)
    else:
        return
        
@app.route('/pool/<pool_slug>', methods=["GET"])
def show_pool(pool_slug):

    if request.method == "GET":

        # get pool_data
        pool_data = db.execute("SELECT * FROM pool WHERE pool_slug IS ?", pool_slug)[0]
        max_left_show = db.execute("SELECT MAX(left_show_in_episode) from contestant")[0]['MAX(left_show_in_episode)']
        if max_left_show:
            current_week = 1 + int(max_left_show)
        else:
            current_week = 1

        # First Get Rows of unique users from <pool_slug> who have registered Picks
        
        rows = db.execute("""SELECT * FROM user
                                JOIN user_pool_map
                                ON user.id = user_pool_map.user_id
                                WHERE EXISTS (SELECT 1 FROM pick WHERE pick.user_pool_map_id = user_pool_map.id)
                                AND pool_id IS (?)
                                ORDER BY user_id""", pool_data["id"])

        # Now iterate over rows getting users picks, left_show_in_episode, and points and adding them to each row-dict
        # formatted [{'pick0': [name],'image_path0': [image_path], 'left_show_in_episode0': [insert week pick0 voted out in] 'pick1' : ____, …, 'points' : user_total_points}]
        for row in rows:

            rows_of_picks = db.execute("""SELECT image_path, left_show_in_episode, name 
                                            FROM contestant JOIN pick
                                            ON contestant.id = pick.contestant_id
                                            WHERE user_pool_map_id IS (SELECT id FROM user_pool_map WHERE user_id = ? AND pool_id = ?)
                                            ORDER BY left_show_in_episode""",
                                            row['user_id'], pool_data["id"])

            # now we iterate over each individual user's individual picks
            user_total_points = 0
            survivors_alive = 0
            # TODO sloppy beginner logic, update this
            for j in range(len(rows_of_picks)):
                # rows_of_picks[j]['x'] x need to be the same as SELECT x from rows_of_picks
                row[f'image_path{j}'] = rows_of_picks[j]['image_path']
                row[f'name{j}'] = rows_of_picks[j]['name']
                # below int conversion requires "or 0" in case of None
                # thus surivors who haven't been voted out, have value 0
                row[f'left_show_in_episode{j}'] = int(rows_of_picks[j]['left_show_in_episode'] or 0)
                if row[f'left_show_in_episode{j}'] == 0:
                    survivors_alive += 1
                # implement POINTS and add it to each row  
                weeks_survived = current_week if row[f'left_show_in_episode{j}'] == 0 else row[f'left_show_in_episode{j}']
                user_total_points += int(pool_data["multiplier"])**(weeks_survived - 1)
            row['points'] = user_total_points
            row['survivors_alive'] = survivors_alive

        if pool_data["pool_type"] == "points":
            rows = sorted(rows, key=lambda x: x['points'], reverse=True)
        if pool_data["pool_type"] == "sole survivor":
            rows = sorted(rows, key=lambda x: x['survivors_alive'], reverse=True)


        return render_template("pool/pool_slug.html", pool_data=pool_data, current_week=current_week, rows=rows, pool_slug=pool_slug)

@app.route('/pool/<pool_slug>/admin', methods=["GET", "POST"])
@pool_admin_required
def pool_admin(pool_slug):

    if request.method == "GET":

        pool_data = db.execute("SELECT * FROM pool WHERE pool_slug IS ?", pool_slug)[0]

        users = db.execute("""SELECT user.id, name FROM user
                                JOIN user_pool_map
                                ON user.id = user_pool_map.user_id
                                WHERE EXISTS (SELECT 1 FROM pick WHERE pick.user_pool_map_id = user_pool_map.id)
                                AND pool_id IS (?)
                                """, pool_data["id"])
        
        invite_tokens = db.execute("SELECT * FROM invite_token WHERE pool_id = ? AND active = 1", pool_data["id"])

        


        return render_template("pool/admin.html", pool_data=pool_data, users=users, pool_slug=pool_slug, invite_tokens=invite_tokens)
    
    # TODO implement POST for change pool info?
    
@app.route('/pool/<pool_slug>/admin/invite-token/<token_id>', methods=["PATCH"])
@pool_admin_required
def generate_invite_token(pool_slug, token_id):
    # PATCH means DE-ACTIVATE
    if request.method == "PATCH":
        pool_id = db.execute("SELECT id FROM pool WHERE pool_slug = ?", pool_slug)[0]["id"]

        # Check if token_id, exists
        token_row = db.execute("SELECT id FROM invite_token WHERE id = ?", token_id)
        if len(token_row) != 1:
            return "Error accessing token records"
        # Token does exist, so we can deactivate it
        db.execute("UPDATE invite_token SET active = 0 WHERE id = ?", token_id)

        return "", 200

            

    
@app.route('/pool/<pool_slug>/admin/remove-user/<user_id>', methods=["DELETE"])
@pool_admin_required
def remove_user(pool_slug, user_id):

    pool_id = db.execute("SELECT id FROM pool WHERE pool_slug = ?", pool_slug)[0]["id"]
    
    db.execute("DELETE FROM user_pool_map WHERE user_id = ? AND pool_id = ?", user_id, pool_id)
    
    return "", 200

@app.route('/pool/<pool_slug>/join/<secret_key>', methods=["GET"])
def invite_token(pool_slug, secret_key):
    if request.method == "GET":
        # Check pool_slug
        pool_row = db.execute("SELECT * FROM pool WHERE pool_slug IS ?", pool_slug)
        if len(pool_row) != 1:
            flash("Could not find a pool with that name.", "error")
            return redirect(url_for('index'))
        pool_data = pool_row[0]

        # Check invite token
        token_row = db.execute("SELECT token FROM invite_token WHERE active = 1 AND pool_id = ?", pool_data["id"])
        if len(token_row) != 1:
            flash("Invalid pool token, contact administrator", "error")
            return(redirect(url_for('show_pool', pool_slug=pool_slug)))
        if token_row[0]["token"] != secret_key:
            flash("Invalid token, contact administrator", "error")
            return(redirect(url_for('show_pool', pool_slug=pool_slug)))
        else:
            # we're good, update session
            if "pools" not in session:
                session["pools"] = {}
            session["pools"][pool_data["id"]] = {"pool_name": pool_data["pool_name"], "pool_slug": pool_data["pool_slug"], "invited": True}
            return(redirect(url_for('join_pool', pool_slug=pool_slug)))
        

@app.route('/pool/<pool_slug>/join', methods=["GET", "POST"])
def join_pool(pool_slug):
    if request.method == "GET":
        
        # Check pool_slug
        pool_row = db.execute("SELECT * FROM pool WHERE pool_slug IS ?", pool_slug)
        if len(pool_row) != 1:
            flash("Could not find a pool with that name.", "error")
            return redirect(url_for('index'))
        pool_data = pool_row[0]

        # Check session for invited
        if session.get("pools").get(pool_data["id"]).get("invited") != True:
            flash("Please use invitiation link.", "error")
            return redirect(url_for('show_pool', pool_slug=pool_slug))

        # get list of survivors
        contestants = db.execute("SELECT * FROM contestant WHERE season = (SELECT current_season FROM settings)")

        # get num_picks

        num_picks = pool_data["num_picks"]
        
        return render_template("pool/join.html", pool_slug=pool_slug, contestants=contestants, num_picks=num_picks, pool_data=pool_data)

    if request.method == "POST":
        
        name = request.form.get("name")
        picks = request.form.getlist("picks")

        if not name:
            flash("Name required.", "error")
        if len(name) < 2:
            flash("Name must be at least 2 characters", "error")
        if len(name) > 20:
            flash("Name must be at most 20 characters", "error")
        name = escape(name)
        

        num_picks = db.execute("SELECT * FROM pool WHERE pool_slug IS ?", pool_slug)[0]["num_picks"]

        #check number of picks
        if len(picks) != num_picks:
            flash("Wrong number of contestants selected.", "error")
            return redirect(url_for('join_pool', pool_slug=pool_slug))
    

        # if user already logged in
        if session.get("user_id"):
            user_id = session.get("user_id")
            user_pool_map_id = db.execute("SELECT id FROM user_pool_map WHERE user_id = ? AND pool_id = (SELECT id FROM pool WHERE pool_slug = ?)", user_id, pool_slug)[0]["id"]
            # check if user has already made picks for this pool
            if len(db.execute("""SELECT * FROM pick
                              JOIN user_pool_map ON pick.user_pool_map_id = user_pool_map.id
                              WHERE user_id = ?
                              AND pool_id = (SELECT id FROM pool WHERE pool_slug = ?)
                              """, user_id, pool_slug)) != 0:
                flash("You've already made your selection for this pool.",  "error")
                return redirect(url_for('show_pool', pool_slug=pool_slug))
        # if new user
        else:
            # Check if user name already in use in that pool
            if len(db.execute("""
                              SELECT name FROM user 
                              JOIN user_pool_map
                              ON user.id = user_pool_map.user_id
                              WHERE name = ?""", name)) != 0:
                flash("That name is already in use in the pool, choose another.", "error")
                return redirect(url_for('join_pool', pool_slug=pool_slug))
            else:
                # add new user to user and user_pool_map
                user_id = db.execute("INSERT INTO user (name) VALUES (?)", name)
                user_pool_map_id = db.execute("INSERT INTO user_pool_map (user_id, pool_id) VALUES (?, (SELECT id FROM pool WHERE pool_slug = ?))", user_id, pool_slug)
        

        for pick in picks:
            db.execute("""INSERT INTO pick (user_pool_map_id, contestant_id)
                VALUES (?, ?)""", 
                user_pool_map_id, int(pick))

        return redirect(url_for('show_pool', pool_slug=pool_slug))
        
    

