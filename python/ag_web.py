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

import ag_generator
import ag_parser
from flask import Flask, request, make_response

# TODO: probably move this over to a Flask config setting if possible?
MAX_WORKERS = 5
AG_DATA_PATH = 'webdata/' # DO NOT PERMIT FILES TO BE SERVED FROM HERE!!!!!

executor = futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
app = Flask(__name__)

def get_ag_path(name):
    ag_string = base64.urlsafe_b64encode(name)
    return os.path.join(AG_DATA_PATH, ag_string)

def ag_exists(name):
    return os.path.isdir(get_ag_path(name))

def create_ag_files(name, nm, xp, depth):
    parent_path = get_ag_path(name)
    
    # Sanity check
    assert not os.path.exists(parent_path)
    
    # Decode and parse (to check for errors) nm/xp files:
    nmstring = nm.decode('base64')
    xpstring = xp.decode('base64')
    parse_errors = ''
    
    
    output_path = os.path.join(parent_path, 'out_'+depth)
    nmfile = os.path.join(parent_path, 'netmodel.nm')
    xpfile = os.path.join(parent_path, 'exploits.xp')
    os.makedirs(output_path)
    
    with open(nmfile, 'w') as nmf, open(xpfile, 'w') as xpf:
        nmf.write(nmstring)
        xpf.write(xpstring)

@app.route('/v0/attackgraphs/', methods=['GET'])
def helloworld():
    return "Hello world"

@app.route('/v0/attackgraphs/', methods=['POST'])
def generate():
    # Check that parameters exist.
    for parm in ('nm', 'xp', 'depth', 'nm'):
        if parm not in request.args:
            return make_response('%s is required' % (parm,), 400)
    
    nm = request.args['nm']
    xp = request.args['xp']
    depth = request.args['depth']
    name = request.args['name']

    # AG exists on path:
    if ag_exists(name):
        return make_response('Attack graph with name %s exists' % (name,), 409)
    # New AG:
    create_ag_files(name, nm, xp, depth)
    return make_response(name, 202)

if __name__ == '__main__': 
    app.run()