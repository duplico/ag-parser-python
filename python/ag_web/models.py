import flask
from flaskext.couchdb import *
from flaskext.login import UserMixin
from flaskext.bcrypt import generate_password_hash, check_password_hash

class User(Document, UserMixin):
    username = TextField()
    pw_hash = TextField()
    email_address = TextField()
    accessible_scenarios = ListField(TextField())
    
    def matches_password(self, raw_password):
        return check_password_hash(self.pw_hash, raw_password)