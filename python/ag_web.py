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
#        Also, "adg" is a valid depth.
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
from StringIO import StringIO
import shutil
import json

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

def get_ag_names():
    # TODO: handle broken stuff
    return [base64.urlsafe_b64decode(name) for name in
            os.listdir(AG_DATA_PATH)]

def get_ag_path(name, depth=None, adg=False):
    assert not (depth and adg)
    ag_string = base64.urlsafe_b64encode(name)
    elements = [AG_DATA_PATH, ag_string]
    if depth:
        elements.append('out_%i' % depth)
    if adg:
        elements.append('adg')
    return os.path.join(*elements)

def get_ag_lockfile(name, depth=None, adg=False):
    return os.path.join(get_ag_path(name, depth, adg), '.lock')

def ag_exists(name, depth=None, adg=False):
    return os.path.isdir(get_ag_path(name, depth, adg))

def get_ag(name, depth=None, adg=False):
    assert(ag_exists(name, depth, adg))
    # TODO: if name in running_futures, etc etc etc...
    ag = nx.read_gpickle(os.path.join(get_ag_path(name, depth, adg), 'ag.pickle'))
    
    # Some kludges to get it to work with GraphML. Luckily, as the API
    # matures this should be less necessary.
    ag.graph = {}
    for n in ag.node:
        for k in ag.node[n]:
            ag.node[n][k]=str(ag.node[n][k])
    return ag

def create_ag_files(name, nm=False, xp=False, depth=False, adg=False):
    assert not (depth and adg)

    parent_path = get_ag_path(name)
    if '\n' in parent_path:
        return 'name is too long'
    
    # Sanity check
    if not depth and not adg:
        # Then we're just trying to GET the paths
        pass
    #    assert not os.path.exists(parent_path)
    
    if nm and xp:
        # Decode and parse (to check for errors) nm/xp files:
        nmstring = nm.decode('base64')
        xpstring = xp.decode('base64')
        try:
            ag_parser.networkmodel.parseString(nmstring)
        except Exception, e:
            return 'Parse error in nm: %s' % (str(e),)
        
        try:
            ag_parser.exploits.parseString(xpstring)
        except Exception, e:
            return 'Parse error in xp: %s' % (str(e),)
        
        # Now go ahead and create the files.    
        os.makedirs(parent_path)
        nmfile = os.path.join(parent_path, 'netmodel.nm')
        xpfile = os.path.join(parent_path, 'exploits.xp')
        with open(nmfile, 'w') as nmf, open(xpfile, 'w') as xpf:
            nmf.write(nmstring)
            xpf.write(xpstring)
    else:
        nmfile = os.path.join(parent_path, 'netmodel.nm')
        xpfile = os.path.join(parent_path, 'exploits.xp')
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
        
    return (nmfile, xpfile)

def get_ag_definition(name):
    files = create_ag_files(name)
    with open(files[0]) as nm, open(files[1]) as xp:
        nm_def = nm.read()
        xp_def = xp.read()
    return (nm_def, xp_def)

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

@app.route('/v0/attackgraphs/', methods=['GET'])
def read_attackgraphs():
    ags = get_ag_names()
    resp = flask.jsonify(attack_graphs=ags)
    #resp = make_response(json.dumps(ags), 200) # Response
    resp.mimetype='text/plain'
    #resp.data = outstring.getvalue()
    return resp

@app.route('/v0/attackgraphs/', methods=['POST'])
def create_nm(): 
    # Check that parameters exist.
    for parm in ('nm', 'xp', 'name'):
        if parm not in request.args:
            return make_response('%s is required' % (parm,), 400)
    
    nm = request.args['nm']
    xp = request.args['xp']
    name = request.args['name']

    # AG exists on path:
    if ag_exists(name):
        return make_response('Attack graph with name %s exists' % (name,), 409)
    
    # New AG:
    ret = create_ag_files(name, nm, xp)
    if type(ret) == str:
        return make_response(ret, 400)
    else:
        return make_response(flask.url_for('generate', name=name), 201)
    # TODO: consider waiting very briefly to see if we can return a 201 fast

@app.route('/v0/attackgraphs/<name>/', methods=['GET'])
def read_attackgraph(name):
    if not ag_exists(name):
        return make_response('Unknown attack graph scenario', 404)
    print get_ag_definition(name)
    return make_response('Exists', 200)

@app.route('/v0/attackgraphs/<name>/', methods=['POST'])
def generate(name): # TODO: don't generate from here; generate elsewhere...
    # TODO: Check for locked AGs that we're not working on, and regen them.
    # Check that parameters exist.
    if 'depth' not in request.args and 'adg' not in request.args:
        return make_response('depth or adg is required', 400)
    if 'depth' in request.args and 'adg' in request.args:
        return make_response('cannot have both depth and adg', 400)
    adg = False
    if 'adg' in request.args:
        adg = True
        depth = False
    if not adg: # State graph
        try:
            depth = int(request.args['depth'])
        except ValueError, e:
            return make_response('depth must be a number', 400)
    
    # AG exists on path:
    if ag_exists(name, depth, adg):
        return make_response('Attack graph exists', 409)
    
    # New AG:
    ret = create_ag_files(name, depth=depth, adg=adg)
    if type(ret) == str:
        return make_response(ret, 400)
    else:
        task = executor.submit(make_attack_graph, name, ret[0], ret[1], depth, adg)
        if name not in running_futures:
            running_futures[name] = dict()
        if adg:
            running_futures[name]['adg'] = task
        else:
            running_futures[name][depth] = task
        print running_futures
        print task.running()
    if not adg:
        return make_response(flask.url_for('read_ag', name=name, depth=depth), 202)
    else:
        return make_response(flask.url_for('read_adg', name=name), 202)
    
# TODO: refactor to DRY
@app.route('/v0/attackgraphs/<name>/adg/', methods=['GET',])
def read_adg(name):
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
def read_ag(name, depth):
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
    app.run(debug=True, host='0.0.0.0')
