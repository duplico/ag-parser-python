import flask
import hashlib
from flaskext.couchdb import *
from flaskext.login import UserMixin
from flaskext.bcrypt import generate_password_hash, check_password_hash
from ag_web import login_manager

class User(Document, UserMixin):
    username = TextField()
    pw_hash = TextField()
    email_address = TextField()
    accessible_scenarios = ListField(TextField())
    admin = BooleanField(default=False)
    
    def matches_password(self, raw_password):
        return check_password_hash(self.pw_hash, raw_password)
    
    def get_auth_token(self):
        hasher = hashlib.sha256()
        hasher.update(self.username)
        hasher.update(self.pw_hash)
        return unicode(hasher.hexdigest())


@login_manager.user_loader
def load_user(username):
    """ Returns none if not found. """
    return User.load(username)