"""
Provides the web service API views.
"""

from flask import request, make_response, render_template, url_for, flash
from flask import redirect
import flask

import ag_generator

from ag_web import app, forms
from ag_web.util import *

@app.route('/', methods=['GET',])
def landing_redirect():
    """
    Redirects to landing page.
    """
    flash('Please access the interactive generator using this URL in the future.', 'info')
    return redirect(url_for('web_landing'))

@app.route('/interactive/', methods=['GET',])
def web_landing():
    """
    Landing page (scenario listing).
    """
    ags = get_ag_overview()
    return render_template('landing.html', ag_table=ags)

@app.route('/interactive/attackgraphs/<name>/', methods=['GET',])
def web_scenario_detail(name):
    """
    Landing page (scenario listing).
    """
    ag = get_ag_overview()[name]
    paths = get_scenario_paths(name)
    with open(paths['nm']) as nm_file, open(paths['xp']) as xp_file:
        nm = nm_file.read()
        xp = xp_file.read()
    return render_template('scenario.html', name=name, ag=ag,
                           nm=nm, xp=xp)

@app.route('/interactive/attackgraphs/<name>/initial.png', methods=['GET',])
def web_scenario_initialstate(name):
    """
    Landing page (scenario listing).
    """
    outstring = get_initial_state_graph_png(name)
    mime = "image/png"
    resp = make_response(outstring.getvalue(), 200) # Response
    resp.mimetype=mime # Correct the MIME according to out_tuple
    resp.implicit_sequence_conversion=False
    resp.data = outstring.getvalue()
    return resp
    
    ag = get_ag_overview()[name]
    paths = get_scenario_paths(name)
    with open(paths['nm']) as nm_file, open(paths['xp']) as xp_file:
        nm = nm_file.read()
        xp = xp_file.read()
    return render_template('scenario.html', name=name, ag=ag,
                           nm=nm, xp=xp)

@app.route('/interactive/attackgraphs/<name>/<graph_type>/<fn>.<ext>', methods=['GET',])
def web_task_download(name, graph_type, fn, ext):
    """
    Attack graph download.
    """
    # filename is formatted {'name_adg.EXT' | 'name_ag_DEPTH.EXT'}
    # Ensure filename is well-formed:
    assert name in get_ag_names()
    # assert fn.split('_')[0] == name
    assert graph_type in ('ag', 'adg')
    # assert fn.split('_')[1] == graph_type
    assert ext.lower() in ('dot', 'pdf', 'xml', 'png')
    
    # Ensure that the request attack graph has been generated:
    adg = graph_type == 'adg'
    depth = False
    if not adg: # Assert the ASG state depth is DONE:
        depth = int(fn.split('_')[-1])
        assert str(depth) in get_ag_tasks(name)[0]
    if adg: # Assert ADG is DONE:
        assert get_ag_tasks(name)[2] == 2
    
    # Get the file:
    
    out_types = {'dot' : 'text/vnd.graphviz',
                 'xml' : 'text/xml', # UTF8=>text
                 'pdf' : 'application/pdf',
                 'png' : 'image/png',
        }
    mime = out_types[ext.lower()]
    ret = get_render(name, depth, mime)
    if type(ret) == tuple: # Error response
        # TODO
        return make_response(*ret)
    
    # If no error, it's a StringIO object (file-like string)
    outstring = ret
    resp = make_response(outstring.getvalue(), 200) # Response
    resp.mimetype=mime # Correct the MIME according to out_tuple
    resp.implicit_sequence_conversion=False
    resp.data = outstring.getvalue()
    return resp
    
@app.route('/interactive/attackgraphs/', methods=['GET', 'POST'])
def web_create_scenario():
    """
    Scenario creation form page.
    """
    form = forms.ScenarioForm(request.form)
    if form.validate_on_submit():
        # Create the new scenario:
        ret = create_scenario_files(form.name.data,
                                    form.nm.data,
                                    form.xp.data)
        if not ret:
            flash('Scenario %s created' % (form.name.data,), 'success')
            return redirect(url_for('web_landing'))
        else:
            # Something bad happened that I wasn't expecting.
            # I/O error maybe?
            flash(ret[0], 'error')
            return render_template('scenario_form.html', form=form)
    return render_template('scenario_form.html', form=form)

@app.route('/interactive/attackgraphs/<name>/add/', methods=['GET', 'POST'])
def web_create_generation_task(name):
    """
    Generation task creation form page.
    """
    form = forms.GenerationTaskForm(request.form)
    # TODO: better error handling.
    if form.validate_on_submit():
        # Create the generation task:
        if form.depth.data: 
            depth = int(form.depth.data)
        else:
            depth = False
        adg = form.graph_type.data == 'adg'        
        ret = new_generation_task(name, depth=depth, adg=adg)
        
        if not ret:
            if adg:
                task_name = 'attack dependency graph'
            else:
                task_name = 'attack state graph of depth %i' % depth
            if not ret:
                flash('Queued generation of %s %s' % (name, task_name), 'success')
            return redirect(url_for('web_scenario_detail', name=name))
        else:
            flash(ret[0], 'error')
            return render_template('task_form.html', form=form, name=name)
    return render_template('task_form.html', form=form, name=name)

@app.route('/interactive/attackgraphs/<name>/delete/', methods=['GET','POST'])
def web_scenario_delete(name):
    """
    Attack graph task restart.
    """
    form = forms.ConfirmForm(request.form)
    # TODO: better error handling.
    if form.validate_on_submit():
        delete_scenario(name)
        flash('Deleted scenario %s' % (name,), 'success')
        return redirect(url_for('web_landing'))
    return render_template('scenario_delete.html', form=form, name=name)

@app.route('/interactive/attackgraphs/<name>/<task>/restart/', methods=['GET','POST'])
def web_task_restart(name, task):
    """
    Attack graph task restart.
    """
    depth = False
    adg = (task == 'adg')
    
    # TODO: validate
    if not adg:
        depth = int(task)
    
    if adg:
        task_name = 'attack dependency graph'
    else:
        task_name = 'attack state graph of depth %i' % depth
    
    form = forms.ConfirmForm(request.form)
    # TODO: better error handling.
    if form.validate_on_submit():
        delete_task(name, depth=depth, adg=adg)
        ret = new_generation_task(name, depth=depth, adg=adg)
        if not ret:
            flash('Restarted generation of %s %s' % (name, task_name), 'success')
            return redirect(url_for('web_scenario_detail', name=name))
        else:
            return make_response(*ret)
    return render_template('task_restart.html', form=form, name=name,
                           task=task_name)

@app.route('/interactive/attackgraphs/<name>/<task>/delete/', methods=['GET','POST'])
def web_task_delete(name, task):
    """
    Attack graph task delete.
    """
    depth = False
    adg = (task == 'adg')
    
    # TODO: validate
    if not adg:
        depth = int(task)
    
    if adg:
        task_name = 'attack dependency graph'
    else:
        task_name = 'attack state graph of depth %i' % depth
    form = forms.ConfirmForm(request.form)
    # TODO: better error handling.
    if form.validate_on_submit():
        delete_task(name, depth=depth, adg=adg)
        flash('Deleted %s %s' % (name, task_name), 'success')
        return redirect(url_for('web_scenario_detail', name=name))
    return render_template('task_delete.html', form=form, name=name,
                           task=task_name)