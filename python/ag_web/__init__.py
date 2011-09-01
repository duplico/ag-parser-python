# Current?
# /interactive/ - landing
# /interactive/name
# /interactive/name/depth
#
# /v0/attackgraphs/
#  GET - nothing useful
#  POST - add new scenario (nm+xp):
#         parameters:
#           name: well-behaved name for the scenario
#           xp: base64-encoded text of the exploit pattern definitions, AG-style
#           nm: base64-encoded text of the network model dfns
#         returns:
#           the URL representing the scenario
# /v0/attackgraphs/<name> (scenario URL)
#  GET - nothing useful
#  POST - generate new attack graph:
#         parameters:
#           depth: depth to generate to
#         returns:
#           URL to get the completed attack graph representation from
# /v0/attackgraphs/<name>/<depth>
#  GET - returns attack graph representation, formatted depending upon the
#        MIME type you have chosen to accept (defaults to Graphviz DOT).
#        Available formats:
#           text/xml - GraphML
#           text/vnd.graphviz - GraphViz DOT
#           image/png - PNG rendering
#           application/pdf - PDF rendering
#          
##########################
# TODO:
#                                  /states
#                                         /<index>
#                       /adg
#                       /nm
#                         /assets/
#                         /facts/
#                       /xp
#                          /<name>
##########################
# futures is backported from 3.2, depends on 'pip install futures'
from concurrent import futures
import os
import base64
import operator.xor
from StringIO import StringIO
import shutil

from flask import Flask, request, make_response
import flask
import networkx as nx

import ag_generator
import ag_parser

# TODO: probably move this over to a Flask config setting if possible?
MAX_WORKERS = 5
AG_DATA_PATH = 'webdata' # DO NOT SERVE FROM THIS PATH! TODO: mode xx0

executor = futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
app = Flask(__name__)

running_futures = dict()

### Utility functions #########################################################

# Dealing with names:

def path_encode_name(name):
    """
    Returns the mapping from a plaintext name to a path-safe name.
    """
    return base64.urlsafe_b64encode(name)

def path_decode_name(name):
    """
    Returns the mapping from a path-safe name to a plaintext name.
    """
    return base64.urlsafe_b64decode(name)
    
def get_ag_names():
    """
    Returns the name of every stored scenario.
    """
    # TODO: handle broken stuff
    return [path_decode_name(name) for name in
            os.listdir(AG_DATA_PATH)]

# Generic task+scenario path/queries:

def get_ag_path(name, depth=None, adg=False):
    """
    Returns the path to either the parent directory of the AG or the AG itself.
    """
    assert not (depth and adg)
    ag_string = path_encode_name(name)
    elements = [AG_DATA_PATH, ag_string]
    if depth:
        elements.append('out_%i' % depth)
    if adg:
        elements.append('adg')
    return os.path.join(*elements)

def get_ag_lockfile(name, depth=None, adg=False):
    """
    Returns the path to the lockfile for a generation task.
    """
    assert operator.xor(depth, adg)
    return os.path.join(get_ag_path(name, depth, adg), '.lock')
    
def ag_exists(name, depth=None, adg=False):
    """
    Returns True if the generation task or scenario directory exists.
    """
    assert not (depth and adg)
    return os.path.isdir(get_ag_path(name, depth, adg))
    
# Scenario management:

def get_scenario_paths(name):
    """
    Returns a 2-dictionary of {"xp": xpfilepath, "nm": nmfilepath}.
    """
    parent_path = get_ag_path(name)
    filenames = ('netmodel.nm', 'exploits.xp')
    pathify = lambda filename : os.path.join(parent_path, filename)
    paths = map(pathify, filenames)
    # Return the dictionary:
    return dict(zip(('nm','xp'), paths))
    
def create_scenario_files(name, nm, xp):
    """
    Returns False on successful scenario creation and error string otherwise.
    """
    if len(name)>100:
        return 'Scenario name too long.'
    
    # Decode and parse (to check for errors) nm/xp files:
    nmstring = nm
    xpstring = xp
    try:
        ag_parser.networkmodel.parseString(nmstring)
        ag_parser.exploits.parseString(xpstring)
    except Exception, e:
        return 'Parse error in nm: %s' % (str(e),)
    
    # Now go ahead and create the files.    
    os.mkdir(parent_path)
    paths = get_scenario_paths(name)
    with open(paths['nm'], 'w') as nmf, open(paths['xp'], 'w') as xpf:
        nmf.write(nmstring)
        xpf.write(xpstring)
    return False

def get_ag_definition(name):
    files = get_scenario_paths(name)
    with open(files['nm']) as nm, open(files['xp']) as xp:
        nm_def = nm.read()
        xp_def = xp.read()
    return (nm_def, xp_def)
    
# Task management:

def create_task_files(name, depth=False, adg=False):
    """
    Returns False on successful task creation and error string otherwise.
    """
    # Sanity check: need at least one of depth, adg:
    assert operator.xor(depth, adg)
    
    if depth:
        output_path = get_ag_path(name, depth)
        # Sanity check
        assert not os.path.exists(output_path)
        os.makedirs(output_path)
    if adg:
        output_path = get_ag_path(name, depth, adg)
        # Sanity check
        assert not os.path.exists(output_path)
        os.makedirs(output_path)
    return False

# Attack graph generation/rendering:

def new_generation_task(name, depth=False, adg=False):
    # Check that parameters exist.
    if not operator.xor(depth, adg):
        return ('must have only one of (depth, adg)', 400)
    # AG exists on path:
    if ag_exists(name, depth, adg):
        # TODO: Check for locked AGs that we're not working on, and regen them.
        return ('Task already exists.', 409)

    ret = create_ag_files(name, depth=depth, adg=adg)
    if ret: # Error:
        return (ret, 400)
    else: # Create new AG/ADG task:
        task = executor.submit(make_attack_graph, name, ret['nm'], ret['xp'],
                               depth, adg)
        if name not in running_futures:
            running_futures[name] = dict()
        if adg:
            running_futures[name]['adg'] = task
        else:
            running_futures[name][depth] = task
        # print running_futures
        # print task.running()
    
    return False # Success, nothing to report.
    
def get_ag(name, depth=None, adg=False):
    """
    Returns the NetworkX graph object for the specified attack graph.
    """
    assert operator.xor(depth, adg)
    assert ag_exists(name, depth, adg)
    # TODO: if name in running_futures, etc etc etc...
    ag = nx.read_gpickle(os.path.join(get_ag_path(name, depth, adg), 'ag.pickle'))
    
    # Some kludges to get it to work with GraphML. Luckily, as the API
    # matures this should be less necessary.
    ag.graph = {}
    for n in ag.node:
        for k in ag.node[n]:
            ag.node[n][k]=str(ag.node[n][k])
    return ag

def make_attack_graph(name, nmfile, xpfile, depth, adg):
    parent_path = get_ag_path(name)
    lockfile = get_ag_lockfile(name, depth, adg)
    open(lockfile, 'w').close() # Touch the lockfile
    ag = ag_generator.build_attack_graph(nmfile, xpfile, depth, not adg)
    pickle_file = os.path.join(get_ag_path(name, depth, adg), 'ag.pickle')
    print pickle_file
    nx.write_gpickle(ag, pickle_file)
    os.remove(lockfile)
    return ag

def write_pdf(name, depth, ag, filehandle):
    render_path = os.path.join(get_ag_path(name, depth), 'ag.pdf')
    if not os.path.isfile(render_path):
        # Generate the PDF
        pd = nx.to_pydot(ag)
        pd.write_pdf(render_path)
    # This might be stupid:
    with open(render_path, 'rb') as rendered:
        filehandle.write(rendered.read())
        filehandle.flush()

def write_png(name, depth, ag, filehandle):
    render_path = os.path.join(get_ag_path(name, depth), 'ag.png')
    if not os.path.isfile(render_path):
        # Generate the PNG
        pd = nx.to_pydot(ag)
        pd.write_png(render_path)
    # This might be stupid:
    with open(render_path, 'rb') as rendered:
        filehandle.write(rendered.read())
        filehandle.flush()
        
####### Web service API views #################################################
@app.route('/v0/attackgraphs/', methods=['GET'])
def api_read_scenarios():
    ags = get_ag_names()
    resp = flask.jsonify(attack_graphs=ags)
    return resp

@app.route('/v0/attackgraphs/', methods=['POST'])
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
def api_read_scenario(name):
    if not ag_exists(name):
        return make_response('Unknown attack graph scenario', 404)
    return make_response('Exists', 200)
    
@app.route('/v0/attackgraphs/<name>/', methods=['POST'])
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
    
# TODO: refactor to DRY
@app.route('/v0/attackgraphs/<name>/adg/', methods=['GET',])
def api_read_adg(name):
    """
    Defaults to dot format.
    """
    # Check for existence
    print ' * getting adg for ' + name
    if not os.path.isdir(get_ag_path(name)):
        return make_response('unknown AG name %s' % (name,), 404)
    print ' * scenario name found'
    if os.path.isfile(get_ag_lockfile(name, adg=True)):
        print ' * locked'
        if name not in running_futures or 'adg' not in running_futures[name]:
            print ' * not running'
            shutil.rmtree(get_ag_path(name)) # TODO: readd: , depth, adg)))
            return make_response('internal error, resubmit generation request',
                                 500)
        print 'what?'
        print running_futures[name]['adg'].exception()
        return make_response('still processing', 400)
    
    if not ag_exists(name, adg=True):
        return make_response('ADG not generated', 404)
    
    # Exists, and we can return it.
    ag = get_ag(name, depth=False, adg=True)
    
    # Defaults to dot
    out_types = {('text', 'vnd.graphviz') : (nx.write_dot, 'text/vnd.graphviz'),
                 ('*', '*') : (nx.write_dot, 'text/vnd.graphviz'),
                 ('text', '*') : (nx.write_dot, 'text/vnd.graphviz'),
                 ('text', 'xml') : (nx.write_graphml, 'text/xml'), # UTF8=>text
                 ('application', 'pdf') : (lambda a,b: write_pdf(name, depth, a, b), 'text/application/pdf'),
                 ('image', 'png') : (lambda a,b: write_png(name,depth,a,b), 'text/image/png'),
        }
    # Check what format the client requested:
    accept_type = flask.request.headers['Accept']
    # This just splits and strips the MIME into a 2-tuple
    accept_mime = tuple(map(lambda a: a.strip().lower(), accept_type.split('/')))
    out_tuple = out_types[accept_mime] # tuple of (callable, canonical MIME)

    outstring = StringIO() # Fake a file handle here to play nice with nx.
    out_tuple[0](ag, outstring) # Call our output function
    resp = make_response(outstring.getvalue(), 200) # Response
    resp.mimetype=out_tuple[1] # Correct the MIME according to out_tuple
    resp.implicit_sequence_conversion=False
    resp.data = outstring.getvalue()
    return resp

@app.route('/v0/attackgraphs/<name>/ag/<int:depth>/', methods=['GET',])
def api_read_ag(name, depth):
    """
    Defaults to dot format.
    """
    # Check for existence
    if not os.path.isdir(get_ag_path(name)):
        return make_response('unknown AG name %s' % (name,), 404)
    if os.path.isfile(get_ag_lockfile(name, depth)):
        if name not in running_futures or depth not in running_futures[name]:
            shutil.rmtree(get_ag_path(name)) # TODO: readd: , depth)))
            return make_response('internal error, resubmit generation request',
                                 500)
        else:
            return make_response('still processing', 122)
    if not ag_exists(name, depth):
        return make_response('ungenerated AG depth', 404)
    
    # Exists, and we can return it.
    ag = get_ag(name, depth)
    
    # Defaults to dot
    out_types = {('text', 'vnd.graphviz') : (nx.write_dot, 'text/vnd.graphviz'),
                 ('*', '*') : (nx.write_dot, 'text/vnd.graphviz'),
                 ('text', '*') : (nx.write_dot, 'text/vnd.graphviz'),
                 ('text', 'xml') : (nx.write_graphml, 'text/xml'), # UTF8=>text
                 ('application', 'pdf') : (lambda a,b: write_pdf(name, depth, a, b), 'text/application/pdf'),
                 ('image', 'png') : (lambda a,b: write_png(name,depth,a,b), 'text/image/png'),
        }
    # Check what format the client requested:
    accept_type = flask.request.headers['Accept']
    # This just splits and strips the MIME into a 2-tuple
    accept_mime = tuple(map(lambda a: a.strip().lower(), accept_type.split('/')))
    out_tuple = out_types[accept_mime] # tuple of (callable, canonical MIME)

    outstring = StringIO() # Fake a file handle here to play nice with nx.
    out_tuple[0](ag, outstring) # Call our output function
    resp = make_response(outstring.getvalue(), 200) # Response
    resp.mimetype=out_tuple[1] # Correct the MIME according to out_tuple
    resp.implicit_sequence_conversion=False
    resp.data = outstring.getvalue()
    return resp

if __name__ == '__main__':    
    app.run(debug=True)
