from flaskext.wtf import Form, BooleanField, TextField, validators
from flaskext.wtf import TextAreaField, RadioField, SelectField, ValidationError
import ag_parser
from ag_web.util import *

# Custom validator for depth+adg/sg
class EmptyIfFieldNotMatches(object):
    """
    Compares the values of two fields.

    :param fieldname:
        The name of the other field to compare to.
    :param value:
        The value that the other field must hold to validate this field.
    :param message:
        Error message to raise in case of a validation error. Can be
        interpolated with `%(other_label)s` and `%(other_name)s` to provide a
        more helpful error.
    """
    def __init__(self, fieldname, req_value, message=None):
        self.fieldname = fieldname
        self.req_value = req_value
        if message:
            self.message = message
        else:
            self.message = 'Generation depth is only allowed for state graphs.'

    def __call__(self, form, field):
        try:
            other = form[self.fieldname]
        except KeyError:
            raise ValidationError(field.gettext(u"Invalid field name '%s'.") % \
                self.fieldname)
        if field.data and other.data != self.req_value:
            raise ValidationError(self.message)

class ScenarioForm(Form):
    """
    Form validator for the interactive specification of scenarios.
    """
    name = TextField('Scenario name', [validators.required(),
                                       validators.length(max=50)])
    xp = TextAreaField('Exploit pattern definition', [validators.required()])
    nm = TextAreaField('Network model definition', [validators.required()])
    
    def validate_xp(form, field):
        try:
            ag_parser.exploits.parseString(field.data)
        except Exception, e:
            raise ValidationError("Correct the following exploit pattern parse error: " + str(e))
        print 'true'
    
    def validate_nm(form, field):
        try:
            ag_parser.networkmodel.parseString(field.data)
        except Exception, e:
            raise ValidationError("Correct the following netmodel parse error: " + str(e))
        print 'true'
    
    def validate_name(form, field):
        if ag_exists(field.data):
            raise ValidationError("Scenario named %s already exists. Choose a different name.")

class GenerationTaskForm(Form):
    """
    Form validator for the interactive creation of generation tasks.
    """
    graph_type = SelectField('Attack Graph Type', choices=[('adg','Dependency graph'),
                                                     ('sg', 'State graph')])
    depth = TextField('Maximum generation depth (state graph only)', 
                      [EmptyIfFieldNotMatches('graph_type', 'sg'),
                       validators.NumberRange(min=1)])

class ConfirmForm(Form):
    """
    Form validator to confirm stuff. Provides POST + CSRF.
    """
    pass