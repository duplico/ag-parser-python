"""
Provides the web service API views.
"""

from flask import request, make_response, render_template
import flask

from ag_web import app
from ag_web.util import *

@app.route('/v0/attackgraphs/', methods=['GET'])
@requires_auth
def api_read_scenarios():
    ags = get_ag_names()
    resp = flask.jsonify(attack_graphs=ags)
    return resp

@app.route('/v0/attackgraphs/', methods=['POST'])
@requires_auth
def api_create_scenario(): 
    # Check that parameters exist.
    for parm in ('nm', 'xp', 'name'):
        if parm not in request.args:
            return make_response('%s is required' % (parm,), 400)
    
    nm = request.args['nm'].decode('base64')
    xp = request.args['xp'].decode('base64')
    name = request.args['name']

    # AG exists on path:
    if ag_exists(name):
        return make_response('Attack graph with name %s exists' % (name,), 409)
    
    # New AG:
    ret = create_scenario_files(name, nm, xp)
    if ret:
        return make_response(ret, 400)
    else:
        return make_response(flask.url_for('api_read_scenario', name=name), 201)

@app.route('/v0/attackgraphs/<name>/', methods=['GET'])
@requires_auth
def api_read_scenario(name):
    if not ag_exists(name):
        return make_response('Unknown attack graph scenario', 404)
    return make_response('Exists', 200)
    
@app.route('/v0/attackgraphs/<name>/', methods=['POST'])
@requires_auth
def api_create_generation_task(name):
    adg = 'adg' in request.args
    try:
        depth = int(request.args['depth'])
    except ValueError, e:
        return make_response('depth must be a number', 400)
    
    ret = new_generation_task(name, depth=depth, adg=adg)
    if ret: # Format is (message, code), so we can unwrap into args like so:
        return make_response(*ret)
    
    # We succeeded, so return the proper URL. We also did all the necessary
    # validation for adg vs. depth above, so this is valid WOLOG:
    if adg:
        return (flask.url_for('api_read_adg', name=name), 202)
    else:
        return (flask.url_for('api_read_ag', name=name, depth=depth), 202)

def api_base_read(name, depth=False):
    out_types = {('text', 'vnd.graphviz') : 'text/vnd.graphviz',
                 ('*', '*') : 'text/vnd.graphviz',
                 ('text', '*') : 'text/vnd.graphviz',
                 ('text', 'xml') : 'text/xml', # UTF8=>text
                 ('application', 'pdf') : 'application/pdf',
                 ('image', 'png') : 'image/png',
        }
    # Check what format the client requested:
    accept_mime = tuple(flask.request.headers['Accept'].split())
    if not accept_mime in out_types:
        return make_response('Unsupported MIME type requested.', 406)
    accept_type = out_types[accept_mime]
    ret = get_render(name, depth, accept_mime)
    if type(ret) == tuple: # Error response
        return make_response(*ret)
    
    # Otherwise, it's a crazy file-like string.
    outstring = ret
    resp = make_response(outstring.getvalue(), 200) # Response
    resp.mimetype=accept_mime # Correct the MIME according to out_tuple
    resp.implicit_sequence_conversion=False
    resp.data = outstring.getvalue()
    return resp

@app.route('/v0/attackgraphs/<name>/adg/', methods=['GET',])
@requires_auth
def api_read_adg(name):
    """
    Defaults to dot format.
    """
    return api_base_read(name)

@app.route('/v0/attackgraphs/<name>/ag/<int:depth>/', methods=['GET',])
@requires_auth
def api_read_ag(name, depth):
    """
    Defaults to dot format.
    """
    return api_base_read(name, depth)