# Current?
# /v0/attackgraphs/
#  GET - get generated attack graphs
#  POST - generate a new attack graph
#         Parameters: name, depth
##########################
# TODO:
# /v1
#   /attackgraphs
#                /<name>
#                       /ag
#                          /<depth>
#                                  /states
#                                         /<index>
#                       /adg
#                       /nm
#                         /assets/
#                         /facts/
#                       /xp
#                          /<name>
#   /attackdependencygraphs/

# futures is backported from 3.2, depends on 'pip install futures'
from concurrent import futures
import os
import base64
from StringIO import StringIO

from flask import Flask, request, make_response
import flask
import networkx as nx

import ag_generator
import ag_parser

#ag_generator.DEBUG = True

# TODO: probably move this over to a Flask config setting if possible?
MAX_WORKERS = 5
AG_DATA_PATH = 'webdata' # DO NOT SERVE FROM THIS PATH! TODO: mode xx0

executor = futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
app = Flask(__name__)

running_futures = dict()

def get_ag_path(name, depth=None):
    ag_string = base64.urlsafe_b64encode(name)
    elements = [AG_DATA_PATH, ag_string]
    if depth:
        elements.append('out_%i' % depth)
    return os.path.join(*elements)

def get_ag_lockfile(name, depth):
    return os.path.join(get_ag_path(name, depth), '.lock')

def ag_exists(name, depth=None):
    return os.path.isdir(get_ag_path(name, depth))

def get_ag(name, depth):
    assert(ag_exists(name, depth))
    # TODO: if name in running_futures, etc etc etc...
    ag = nx.read_gpickle(os.path.join(get_ag_path(name, depth), 'ag.pickle'))
    
    # Some kludges to get it to work with GraphML. Luckily, as the API
    # matures this should be less necessary.
    ag.graph = {}
    for n in ag.node:
        for k in ag.node[n]:
            ag.node[n][k]=str(ag.node[n][k])
    return ag

def create_ag_files(name, nm, xp, depth):
    # Returns errors, or None if none.
    parent_path = get_ag_path(name)
    if '\n' in parent_path:
        return 'name is too long'
    
    # Sanity check
    assert not os.path.exists(parent_path)
    
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
    output_path = get_ag_path(name, depth)
    nmfile = os.path.join(parent_path, 'netmodel.nm')
    xpfile = os.path.join(parent_path, 'exploits.xp')
    os.makedirs(output_path)
    
    with open(nmfile, 'w') as nmf, open(xpfile, 'w') as xpf:
        nmf.write(nmstring)
        xpf.write(xpstring)
    
    return (nmfile, xpfile)

def make_attack_graph(name, nmfile, xpfile, depth):
    parent_path = get_ag_path(name)
    lockfile = get_ag_lockfile(name, depth)
    open(lockfile, 'w').close() # Touch the lockfile
    ag = ag_generator.build_attack_graph(nmfile, xpfile, depth, True)
    pickle_file = os.path.join(get_ag_path(name, depth), 'ag.pickle')
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
    with open(render_path, 'rb') as rendered:
        filehandle.write(rendered.read())
        filehandle.flush()

def write_png(name, depth, ag, filehandle):
    render_path = os.path.join(get_ag_path(name, depth), 'ag.png')
    if not os.path.isfile(render_path):
        # Generate the PNG
        pd = nx.to_pydot(ag)
        pd.write_png(render_path)
    with open(render_path, 'rb') as rendered:
        filehandle.write(rendered.read())
        filehandle.flush()

@app.route('/v0/attackgraphs/', methods=['GET'])
def helloworld():
    name = request.args.get('name', 'NoName')
    print name
    return "Hello world, %s" % (name,)

@app.route('/v0/attackgraphs/', methods=['POST'])
def generate(): # TODO: don't generate from here; generate elsewhere...
    # TODO: Check for locked AGs that we're not working on, and regen them.
    
    # Check that parameters exist.
    for parm in ('nm', 'xp', 'depth', 'nm'):
        if parm not in request.args:
            return make_response('%s is required' % (parm,), 400)
    
    nm = request.args['nm']
    xp = request.args['xp']
    try:
        depth = int(request.args['depth'])
    except ValueError, e:
        return make_response('depth must be a number', 400)
    name = request.args['name']

    # AG exists on path:
    if ag_exists(name):
        return make_response('Attack graph with name %s exists' % (name,), 409)
    
    # New AG:
    ret = create_ag_files(name, nm, xp, depth)
    if type(ret) == str:
        return make_response(ret, 400)
    else:
        task = executor.submit(make_attack_graph, name, ret[0], ret[1], depth)
        if name not in running_futures:
            running_futures[name] = dict()
        running_futures[name][depth] = task
        print running_futures
        print task.running()
    
    return make_response(flask.url_for('read_ag', name=name, depth=depth), 202)
    # TODO: consider waiting very briefly to see if we can return a 201 fast

@app.route('/v0/attackgraphs/<name>/<int:depth>/', methods=['GET',])
def read_ag(name, depth):
    """
    Defaults to dot format.
    """
    # Check for existence
    if not os.path.isdir(get_ag_path(name)):
        return make_response('unknown AG name %s' % (name,), 404)
    if os.path.isfile(get_ag_lockfile(name, depth)):
        if name not in running_futures or depth not in running_futures[name]:
            os.rmdir(get_ag_path(get_ag_path(name))) # TODO: readd: , depth)))
            return make_response('internal error, resubmit generation request',
                                 500)
        else:
            return make_response('still processing', 122)
    
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