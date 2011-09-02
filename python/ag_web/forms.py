from flaskext.wtf import Form, BooleanField, TextField, validators
from flaskext.wtf import TextAreaField
import ag_parser
from ag_web.util import *

class ScenarioForm(Form):
    name = TextField('Scenario name', [validators.required(),
                                       validators.length(max=50)])
    xp = TextAreaField('Exploit pattern definition', [validators.required()])
    nm = TextAreaField('Network model definition', [validators.required()])
    
    def validate_xp(form, field):
        try:
            ag_parser.exploits.parseString(field.data)
        except Exception, e:
            raise validators.ValidationError("Correct the following exploit pattern parse error: " + str(e))
        print 'true'
    
    def validate_nm(form, field):
        try:
            ag_parser.networkmodel.parseString(field.data)
        except Exception, e:
            raise validators.ValidationError("Correct the following netmodel parse error: " + str(e))
        print 'true'
    
    def validate_name(form, field):
        if ag_exists(field.data):
            raise validators.ValidationError("Scenario named %s already exists. Choose a different name.")

class GenerationTaskForm(Form):
    pass