import csv
import datetime
import pytz
import requests
import urllib
import uuid

from flask import flash, make_response, redirect, render_template, request, session, url_for
from functools import wraps
from urllib.parse import urlparse


def apology(message, code=400):
    """Render message as an apology to user."""

    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [
            ("-", "--"),
            (" ", "-"),
            ("_", "__"),
            ("?", "~q"),
            ("%", "~p"),
            ("#", "~h"),
            ("/", "~s"),
            ('"', "''"),
        ]:
            s = s.replace(old, new)
        return s

    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/latest/patterns/viewdecorators/
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for('login', next=urlparse(request.url).path))
        return f(*args, **kwargs)

    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # TODO does this work, bool or string?
        if session.get("is_site_admin") != True:
            flash("You do not have permission to access the admin panel.", "error")
            return make_response(redirect(url_for('login')), 403)
        return f(*args, **kwargs)
    return decorated_function

