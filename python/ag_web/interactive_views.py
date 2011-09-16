"""
Provides the web service API views.
"""

from flask import request, make_response, render_template, url_for, flash
from flask import redirect
import flask

from flaskext.bcrypt import generate_password_hash, check_password_hash

from flaskext.login import login_user, login_required, logout_user
from flaskext.login import current_user

import ag_generator

from ag_web import app, forms, couchdb_manager
from ag_web.util import *
from ag_web import models

@app.route('/', methods=['GET',])
@login_required
def landing_redirect():
    """
    Redirects to landing page.
    """
    flash('Please access the interactive generator using this URL in the future.', 'info')
    return redirect(url_for('web_landing'))

@app.route('/interactive/', methods=['GET',])
@login_required
def web_landing():
    """
    Landing page (scenario listing).
    """
    ags = get_ag_overview(username=current_user.username)
    return render_template('landing.html', ag_table=ags)

@app.route('/interactive/auth/login/', methods=['GET', 'POST',])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password_raw = form.password.data
        user = models.User.load(username)
        if not user or not user.matches_password(password_raw):
            flash("Unknown user or non-matching password.", 'error')
            return render_template("login.html", form=form)
        # login and validate the user...
        login_user(user)
        flash("Logged in successfully.", 'success')
        return redirect(request.args.get("next") or url_for("web_landing"))
    return render_template("login.html", form=form)

@app.route('/interactive/auth/register/', methods=['GET', 'POST',])
def register():
    form = forms.RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password_raw = form.password.data
        email = form.email.data
        user = models.User.load(username)
        if user:
            flash("User already exists by that name.", 'error')
            return render_template("register.html", form=form)
        password_hash = unicode(generate_password_hash(password_raw))
        user = models.User(username=username, pw_hash=password_hash,
                           email_address=email, accessible_scenarios=[])
        user.id = username
        user.store()
        couchdb_manager.sync(app)
        ## login and validate the user...
        login_user(user)
        flash("User created successfully.", 'success')
        return redirect(request.args.get("next") or url_for("web_landing"))
    return render_template("register.html", form=form)

@app.route("/interactive/auth/logout/")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/interactive/attackgraphs/c/<name>/', methods=['GET',])
@login_required
def web_scenario_detail(name):
    """
    Landing page (scenario listing).
    """
    ag = get_ag_overview(username=current_user.username)[name]
    paths = get_scenario_paths(name, username=current_user.username)
    with open(paths['nm']) as nm_file, open(paths['xp']) as xp_file:
        nm = nm_file.read()
        xp = xp_file.read()
    return render_template('scenario.html', name=name, ag=ag,
                           nm=nm, xp=xp)

@app.route('/interactive/attackgraphs/c/<name>/initial.png', methods=['GET',])
@login_required
def web_scenario_initialstate(name):
    """
    Landing page (scenario listing).
    """
    outstring = get_initial_state_graph_png(name, 
                                            username=current_user.username)
    mime = "image/png"
    resp = make_response(outstring.getvalue(), 200) # Response
    resp.mimetype=mime # Correct the MIME according to out_tuple
    resp.implicit_sequence_conversion=False
    resp.data = outstring.getvalue()
    return resp
    
    ag = get_ag_overview(username=current_user.username)[name]
    paths = get_scenario_paths(name, username=current_user.username)
    with open(paths['nm']) as nm_file, open(paths['xp']) as xp_file:
        nm = nm_file.read()
        xp = xp_file.read()
    return render_template('scenario.html', name=name, ag=ag,
                           nm=nm, xp=xp)

@app.route('/interactive/attackgraphs/c/<name>/<graph_type>/<fn>.<ext>', methods=['GET',])
@login_required
def web_task_download(name, graph_type, fn, ext):
    """
    Attack graph download.
    """
    # filename is formatted {'name_adg.EXT' | 'name_ag_DEPTH.EXT'}
    # Ensure filename is well-formed:
    assert name in get_ag_names(username=current_user.username)
    # assert fn.split('_')[0] == name
    assert graph_type in ('ag', 'adg')
    # assert fn.split('_')[1] == graph_type
    assert ext.lower() in ('dot', 'pdf', 'xml', 'png')
    
    aggregate = 'aggregate' in request.args
    
    # Ensure that the request attack graph has been generated:
    adg = graph_type == 'adg'
    depth = False
    if not adg: # Assert the ASG state depth is DONE:
        depth = int(fn.split('_')[-1])
        assert str(depth) in get_ag_tasks(name, username=current_user.username)[0]
    if adg: # Assert ADG is DONE:
        assert get_ag_tasks(name, username=current_user.username)[2] == 2
    
    # Get the file:
    
    out_types = {'dot' : 'text/vnd.graphviz',
                 'xml' : 'text/xml', # UTF8=>text
                 'pdf' : 'application/pdf',
                 'png' : 'image/png',
        }
    mime = out_types[ext.lower()]
    ret = get_render(name, depth, mime, merge=aggregate, 
                     username=current_user.username)
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
@login_required
def web_create_scenario():
    """
    Scenario creation form page.
    """
    form = forms.ScenarioForm(request.form)
    if form.validate_on_submit():
        # Create the new scenario:
        ret = create_scenario_files(form.name.data,
                                    form.nm.data,
                                    form.xp.data, 
                                    username=current_user.username)
        if not ret:
            flash('Scenario %s created' % (form.name.data,), 'success')
            return redirect(url_for('web_landing'))
        else:
            # Something bad happened that I wasn't expecting.
            # I/O error maybe?
            flash(ret[0], 'error')
            return render_template('scenario_form.html', form=form)
    return render_template('scenario_form.html', form=form)
### I AM HERE. ##
@app.route('/interactive/attackgraphs/c/<name>/add/', methods=['GET', 'POST'])
@login_required
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
        ret = new_generation_task(name, depth=depth, adg=adg,
                                  username=current_user.username)
        
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

@app.route('/interactive/attackgraphs/c/<name>/delete/', methods=['GET','POST'])
@login_required
def web_scenario_delete(name):
    """
    Attack graph task restart.
    """
    form = forms.ConfirmForm(request.form)
    # TODO: better error handling.
    if form.validate_on_submit():
        delete_scenario(name, username=current_user.username)
        flash('Deleted scenario %s' % (name,), 'success')
        return redirect(url_for('web_landing'))
    return render_template('scenario_delete.html', form=form, name=name)

@app.route('/interactive/attackgraphs/c/<name>/<task>/restart/', methods=['GET','POST'])
@login_required
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
        delete_task(name, depth=depth, adg=adg, 
                    username=current_user.username)
        ret = new_generation_task(name, depth=depth, adg=adg,
                                  username=current_user.username)
        if not ret:
            flash('Restarted generation of %s %s' % (name, task_name), 'success')
            return redirect(url_for('web_scenario_detail', name=name))
        else:
            return make_response(*ret)
    return render_template('task_restart.html', form=form, name=name,
                           task=task_name)

@app.route('/interactive/attackgraphs/c/<name>/<task>/delete/', methods=['GET','POST'])
@login_required
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
        delete_task(name, depth=depth, adg=adg, username=current_user.username)
        flash('Deleted %s %s' % (name, task_name), 'success')
        return redirect(url_for('web_scenario_detail', name=name))
    return render_template('task_delete.html', form=form, name=name,
                           task=task_name)