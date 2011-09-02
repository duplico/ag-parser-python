"""
Provides the web service API views.
"""

from flask import request, make_response, render_template, url_for, flash
from flask import redirect
import flask

from ag_web import app, forms
from ag_web.util import *

@app.route('/interactive/', methods=['GET',])
def web_landing():
    """
    Defaults to dot format.
    """
    ags = get_ag_overview()
    return render_template('landing.html', ag_table=ags)

@app.route('/interactive/attackgraphs/', methods=['GET', 'POST'])
def web_create_scenario():
    """
    Defaults to dot format.
    """
    form = forms.ScenarioForm(request.form)
    if form.validate_on_submit():
        # Create the new scenario:
        ret = create_scenario_files(form.name.data,
                                    form.nm.data,
                                    form.xp.data)
        if not ret:
            flash('Submitted!')
            return redirect(url_for('web_landing'))
        else:
            # Something bad happened that I wasn't expecting.
            # I/O error maybe?
            assert False
    return render_template('scenario_form.html', form=form)