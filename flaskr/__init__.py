import os

from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flaskr import auth, blog, db

csrf = CSRFProtect()

def create_app(test_config=None):
    # create and configure the app
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(
        SECRET_KEY='dev',
        WTF_CSRF_SECRET_KEY='hunter2',
        DATABASE=os.path.join(app.instance_path, 'flaskr.sqlite'),
        # FLAW 5
        #MAX_FORM_PARTS='15',
        #MAX_FORM_MEMORY_SIZE='10000',
        #MAX_CONTENT_LENGTH='200000',
    )

    if test_config is None:
        # load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # load the test config if passed in
        app.config.from_mapping(test_config)

    # ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    db.init_app(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(blog.bp)
    app.add_url_rule('/', endpoint='index')
    csrf.init_app(app)

    # FLAW 1
    csrf.exempt(blog.delete)

    return app
