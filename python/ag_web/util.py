import os
import base64
import operator
from StringIO import StringIO
import shutil

import networkx as nx

import ag_generator
import ag_parser

from ag_web import executor, running_futures, AG_DATA_PATH

from functools import wraps
from flask import request, Response

def check_auth(username, password):
    """This function is called to check if a username /
    password combination is valid.
    """
    return username == 'isec' and password == 'security2008'

def authenticate():
    """Sends a 401 response that enables basic auth"""
    return Response(
    'Could not verify your access level for that URL.\n'
    'You have to login with proper credentials', 401,
    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

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
    # TODO: may not work:
    if not os.path.isdir(AG_DATA_PATH):
        os.makedirs(AG_DATA_PATH)
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
    assert operator.xor(bool(depth), adg)
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
        return ('Scenario name too long.', 400)
    
    # Decode and parse (to check for errors) nm/xp files:
    nmstring = nm
    xpstring = xp
    try:
        ag_parser.networkmodel.parseString(nmstring)
        ag_parser.exploits.parseString(xpstring)
    except Exception, e:
        return ('Parse error: %s' % (str(e),), 400)
    
    # Now go ahead and create the files.    
    os.makedirs(get_ag_path(name))
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
    
def delete_scenario(name):
    directory = get_ag_path(name)
    if name in running_futures:
        for ag in running_futures[name]:
            future = running_futures[name][ag]
            if future.running():
                assert future.cancel()
        del running_futures[name]
    shutil.rmtree(directory)

# Task management:

def delete_task(name, depth=False, adg=False):
    assert operator.xor(bool(depth), adg)
    directory = get_ag_path(name, depth=depth, adg=adg)
    test = 'adg'
    if not adg:
        test = depth
    if name in running_futures and test in running_futures[name]:
        future = running_futures[name][test]
        if future.running():
            assert future.cancel()
        del running_futures[name]
    shutil.rmtree(directory)

def create_task_files(name, depth=False, adg=False):
    """
    Returns False on successful task creation and error string otherwise.
    """
    # Sanity check: need at least one of depth, adg:
    assert operator.xor(bool(depth), adg)
    
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

def is_locked(name, depth=False, adg=False):
    assert operator.xor(bool(depth), adg)
    return os.path.isfile(get_ag_lockfile(name, depth, adg))

def get_ag_tasks(name):
    if not ag_exists(name):
        return False
    done_depths = []
    locked_depths = []
    adg = 0
    for directory in os.listdir(get_ag_path(name)):
        if directory.startswith('out_'):
            depth = int(directory.split('_')[1])
            if is_locked(name, depth):
                locked_depths.append(str(depth))
            else:
                done_depths.append(str(depth))
        elif directory == 'adg':
            if is_locked(name, adg=True):
                adg = 1
            else:
                adg = 2
    return (done_depths, locked_depths, adg)

def get_ag_overview():
    ags = dict()
    for ag in get_ag_names():
        ags[ag] = get_ag_tasks(ag)
    return ags

# Attack graph generation/rendering:

def new_generation_task(name, depth=False, adg=False):
    # Check that parameters exist.
    if not operator.xor(bool(depth), adg):
        return ('must have only one of (depth, adg)', 400)
    # AG exists on path:
    if ag_exists(name, depth, adg):
        # TODO: Check for locked AGs that we're not working on, and regen them.
        return ('Task already exists.', 409)

    ret = create_task_files(name, depth=depth, adg=adg)
    if ret: # Error:
        return (ret, 400)
    else: # Create new AG/ADG task:
        paths = get_scenario_paths(name)
        task = executor.submit(make_attack_graph, name, paths['nm'], 
                               paths['xp'], depth, adg)
        if name not in running_futures:
            running_futures[name] = dict()
        if adg:
            running_futures[name]['adg'] = task
        else:
            running_futures[name][depth] = task
    
    return False # Success, nothing to report.
    
def get_ag(name, depth=None, adg=False):
    """
    Returns the NetworkX graph object for the specified attack graph.
    """
    assert operator.xor(bool(depth), adg)
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
    nx.write_gpickle(ag, pickle_file)
    os.remove(lockfile)
    return ag

def write_pdf(name, depth, ag, filehandle, merged=False):
    render_path = os.path.join(get_ag_path(name, depth), 'ag.pdf')
    if merged:
        render_path += '.merged'
    if not os.path.isfile(render_path):
        # Generate the PDF
        pd = nx.to_pydot(ag)
        pd.write_pdf(render_path)
    # This might be stupid:
    with open(render_path, 'rb') as rendered:
        filehandle.write(rendered.read())
        filehandle.flush()

def write_png(name, depth, ag, filehandle, merged=False):
    render_path = os.path.join(get_ag_path(name, depth), 'ag.png')
    if merged:
        render_path += '.merged'
    if not os.path.isfile(render_path):
        # Generate the PNG
        pd = nx.to_pydot(ag)
        pd.write_png(render_path)
    # This might be stupid:
    with open(render_path, 'rb') as rendered:
        filehandle.write(rendered.read())
        filehandle.flush()

def get_render(name,depth=False, accept_type='text/vnd.graphviz', merge=False):
    """
    Defaults to dot format.
    """
    # Type configuration:
    adg = False
    if not depth:
        adg = True
    
    # Input validation on scenario/task existence:
    if not ag_exists(name):
        return ('Unknown scenario name', 404)
    if not ag_exists(name, depth, adg):
        return ('Unknown generation task', 404)
    
    # Check for lock
    if is_locked(name, depth, adg):
        if name not in running_futures or depth not in running_futures[name]:
            shutil.rmtree(get_ag_path(name, depth, adg)) # TODO?
            return ('internal error, resubmit generation request', 500)
        else:
            return ('still processing', 122)
    if not ag_exists(name, depth):
        return ('unrequested AG depth', 404)
    
    # Exists, and we can return it.
    ag = get_ag(name, depth, adg)
    
    if merge:
        ag = ag_generator.aggregate_topologies(ag)
    
    # Defaults to dot
    out_types = {'text/vnd.graphviz' : nx.write_dot,
                 '*/*' : nx.write_dot,
                 'text/*' : nx.write_dot,
                 'text/xml' : nx.write_graphml, # UTF8=>text
                 'application/pdf' : lambda a,b: write_pdf(name, depth, a, b, merge),
                 'image/png' : lambda a,b: write_png(name,depth,a,b, merge),
        }
    # This just splits and strips the MIME into a 2-tuple
    accept_mime = tuple(map(lambda a: a.strip().lower(), accept_type.split('/')))
    out_fun = out_types[accept_type] # output function
    outstring = StringIO() # Dummy up a file-like string
    out_fun(ag, outstring) # Call our output function on it
    return outstring

def get_initial_state_graph_png(name):
    nmfile = get_scenario_paths(name)['nm']
    initial_graph = ag_generator.viz_nm(nmfile) # NX object
    
    outstring = StringIO()
    
    render_path = os.path.join(get_ag_path(name), 'initial.png')
    if not os.path.isfile(render_path):
        # Generate the PNG
        pd = nx.to_pydot(initial_graph)
        pd.write_png(render_path)
    # This might be stupid:
    with open(render_path, 'rb') as rendered:
        outstring.write(rendered.read())
        outstring.flush()    

    return outstring