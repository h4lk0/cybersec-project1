import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from hashlib import md5
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        # FLAW 2 
        # Validate password length
        #if len(password) < 8:
        #    error = "Minimum password length is 8 characters"
        #elif len(password) > 64:
        #    error = "Maximum password length is 64 characters"
        # Check if on list of known weak passwords
        #with open('owasp-10k-worst-passwords.txt') as f:
        #    if password in f.read():
        #        error = "Common insecure password. Try again."

        if error is None:
            try:
            # FLAW 3
                #db.execute(
                #    "INSERT INTO user (username, password) VALUES (?, ?)",
                #    (username, generate_password_hash(password)),
                #)
                db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, md5(password.encode()).hexdigest()),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        # FLAW 3
        #elif not check_password_hash(user['password'], password):
        elif user['password'] != md5(password.encode()).hexdigest():
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view