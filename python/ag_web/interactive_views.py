"""
Provides the web service API views.
"""

from flask import request, make_response, render_template
import flask

from ag_web import app

@app.route('/interactive/attackgraphs/', methods=['GET',])
def web_landing():
    """
    Defaults to dot format.
    """
    return render_template('scenario_form.html')