# Current:
# /v0/attackgraphs/
#  GET - get generated attack graphs
#  POST - generate a new attack graph
#         Parameters: name, depth
##########################
# TODO:
# /v1
#   /attackgraphs
#                /<name>
#                       /nm
#                         /assets
#                         /facts
#                       /xp
#                          /<name>
#   /attackdependencygraphs/

import ag_generator
import ag_parser
from flask import Flask, request

app = Flask(__name__)

@app.route('/v0/attackgraphs/', methods=['GET'])
def helloworld():
    return "Hello world"

@app.route('/v0/attackgraphs/', methods=['POST'])
def generate():
    nm = request.args.get('nm','')
    xp = request.args.get('xp','')
    depth = request.args.get('depth','5')
    return nm + xp + depth

if __name__ == '__main__': app.run()