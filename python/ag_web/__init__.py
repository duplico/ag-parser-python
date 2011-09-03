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
from flask import Flask

# TODO: probably move this over to a Flask config setting if possible?
MAX_WORKERS = 5
AG_DATA_PATH = 'ag_web/webdata' # DO NOT SERVE FROM THIS PATH! TODO: mode xx0

# Handle concurrency:
executor = futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)
running_futures = dict()

# Start the web application:
app = Flask(__name__)
app.secret_key = '3D193C6B2B50A396393F4D42F90CB65F3475D9948E5D4290C4E48118FD99'
import ag_web.api_views
import ag_web.interactive_views
import ag_web.util