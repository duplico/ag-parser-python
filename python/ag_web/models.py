import flask
import hashlib
from flaskext.couchdb import *
from flaskext.login import UserMixin
from flaskext.bcrypt import generate_password_hash, check_password_hash
from ag_web import login_manager, couchdb_manager

class User(Document, UserMixin):
    doc_type = 'user'
    username = TextField()
    pw_hash = TextField()
    email_address = TextField()
    admin = BooleanField(default=False)
    
    shared_scenarios = ListField(DictField(Mapping.build(
        dest_username=TextField(),
        src_username=TextField(), # DENORMALIZATION IS AWESOME :)
        ag_name=TextField())))
    
    shared_with = ViewField('User', '''\
    function (doc) {
        if (doc.doc_type == 'user') {
            doc.shared_scenarios.forEach(function (scenario) {
                emit(scenario.dest_username, scenario);
            });
        };
    }''', wrapper=Row)
    
    def matches_password(self, raw_password):
        return check_password_hash(self.pw_hash, raw_password)
    
    def get_auth_token(self):
        hasher = hashlib.sha256()
        hasher.update(self.username)
        hasher.update(self.pw_hash)
        return unicode(hasher.hexdigest())
    
    def available_scenarios(self):
        explicit = [(row.value['src_username'], row.value['ag_name']) \
                    for row in User.shared_with[self.username]]
        implicit = [(row.value['src_username'], row.value['ag_name']) \
                    for row in User.shared_with['*']]
        return list(set(explicit + implicit))

couchdb_manager.add_document(User)
        
@login_manager.user_loader
def load_user(username):
    """ Returns none if not found. """
    return User.load(username)