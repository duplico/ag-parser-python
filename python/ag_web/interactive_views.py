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
    ags = dict()
    ags[current_user.username] = get_ag_overview(username=current_user.username)
    ags.update(get_shared_ag_overview(username=current_user.username))
    ag_render_list = []
    prev_owner = ''
    
    owner = current_user.username
    for name in ags[owner]:
        ag_render_list.append((owner, name, owner!=prev_owner))
        prev_owner = owner
    
    for owner in ags:
        if owner == current_user.username:
            continue
        for name in ags[owner]:
            ag_render_list.append((owner, name, owner!=prev_owner))
            prev_owner = owner
    
    return render_template('landing.html', ag_table=ags,
                           ag_render_list=ag_render_list)

@app.route('/interactive/auth/login/', methods=['GET', 'POST',])
def login():
    form = forms.LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password_raw = form.password.data
        user = models.load_user(username)
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
        username = form.username.data.lower()
        password_raw = form.password.data
        email = form.email.data
        user = models.load_user(username)
        if user:
            flash("User already exists by that name.", 'error')
            return render_template("register.html", form=form)
        password_hash = unicode(generate_password_hash(password_raw))
        user = models.User(username=username, pw_hash=password_hash,
                           email_address=email, shared_scenarios=[])
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

@app.route('/interactive/auth/change_password/', methods=['GET', 'POST',])
@login_required
def change_password():
    form = forms.PasswordForm()
    if form.validate_on_submit():
        new_password_raw = form.password.data
        current_password_raw = form.current_password.data

        if not current_user or not current_user.matches_password(current_password_raw):
            flash("Incorrect current password.", 'error')
            return render_template("change_password.html", form=form)
        
        
        password_hash = unicode(generate_password_hash(new_password_raw))
        current_user.pw_hash = password_hash
        current_user.store()
        couchdb_manager.sync(app)

        flash("Password changed successfully.", 'success')
        return redirect(url_for("web_landing"))
    return render_template("change_password.html", form=form)
    
@app.route('/interactive/attackgraphs/<owner>/<name>/', methods=['GET',])
@login_required
def web_scenario_detail(owner, name):
    """
    Landing page (scenario listing).
    """
    if owner != current_user.username:
        scenario_name = get_owned_ag_name(owner, name)
        if scenario_name not in current_user.available_scenarios():
            return make_response('This scenario (if it even exists) has not ' \
                                 'been shared with you.', 401)
        owner_username = owner
    else:
        owner_username = current_user.username
    
    overview = get_ag_overview(username=owner_username)
    if name in overview:
        ag = overview[name]
    else:
        return make_response('Not found', 404)
    paths = get_scenario_paths(name, username=owner_username)
    with open(paths['nm']) as nm_file, open(paths['xp']) as xp_file:
        nm = nm_file.read()
        xp = xp_file.read()
    return render_template('scenario.html', name=name, ag=ag,
                           nm=nm, xp=xp, owner=owner_username)

@app.route('/interactive/attackgraphs/<owner>/<name>/initial.png', methods=['GET',])
@login_required
def web_scenario_initialstate(owner, name):
    """
    Landing page (scenario listing).
    """
    if owner != current_user.username:
        scenario_name = get_owned_ag_name(owner, name)
        if scenario_name not in current_user.available_scenarios():
            return make_response('This scenario (if it even exists) has not ' \
                                 'been shared with you.', 401)
        owner_username = owner
    else:
        owner_username = current_user.username
    
    outstring = get_initial_state_graph_png(name, 
                                            username=owner_username)
    mime = "image/png"
    resp = make_response(outstring.getvalue(), 200) # Response
    resp.mimetype=mime # Correct the MIME according to out_tuple
    resp.implicit_sequence_conversion=False
    resp.data = outstring.getvalue()
    return resp

@app.route('/interactive/attackgraphs/<owner>/<name>/<graph_type>/<fn>.<ext>', methods=['GET',])
@login_required
def web_task_download(owner, name, graph_type, fn, ext):
    """
    Attack graph download.
    """
    if owner != current_user.username:
        scenario_name = get_owned_ag_name(owner, name)
        if scenario_name not in current_user.available_scenarios():
            return make_response('This scenario (if it even exists) has not ' \
                                 'been shared with you.', 401)
        owner_username = owner
    else:
        owner_username = current_user.username
        
    # filename is formatted {'name_adg.EXT' | 'name_ag_DEPTH.EXT'}
    # Ensure filename is well-formed:
    assert name in get_ag_names(username=owner_username)
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
        assert str(depth) in get_ag_tasks(name, username=owner_username)[0]
    if adg: # Assert ADG is DONE:
        assert get_ag_tasks(name, owner_username)[2] == 2
    
    # Get the file:
    
    out_types = {'dot' : 'text/vnd.graphviz',
                 'xml' : 'text/xml', # UTF8=>text
                 'pdf' : 'application/pdf',
                 'png' : 'image/png',
        }
    mime = out_types[ext.lower()]
    ret = get_render(name, depth, mime, merge=aggregate, 
                     username=owner_username)
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

@app.route('/interactive/attackgraphs/<owner>/<name>/share/', methods=['GET', 'POST'])
@login_required
def web_scenario_share(owner, name):
    """
    Scenario sharing form page.
    """
    if owner != current_user.username:
        return make_response("Can't share scenarios that aren't yours.", 401)
    
    owner_username = owner
    owner_user = models.load_user(owner_username)
    form = forms.ShareForm()
    
    if form.validate_on_submit(): # TODO: prevent duplicates.
        username = form.username.data
        if username != '*':
            destination_user = models.load_user(username)
            if not destination_user:
                return make_response('User does not exist. Furthermore, the ' \
                                     'form validator had a problem.', 500)
        owner_user.shared_scenarios.append(dict(ag_name=name,
                                                dest_username=username,
                                                src_username=owner_username))
        owner_user.store()
        couchdb_manager.sync(app)
        flash('Scenario successfully shared.', 'success')
        return redirect(url_for('web_scenario_detail', owner=owner, name=name))
    return render_template('scenario_share.html', form=form, name=name, owner=owner_username)

@app.route('/interactive/attackgraphs/<owner>/<name>/unshare/<dest_user>/', methods=['GET', 'POST'])
@login_required
def web_scenario_unshare(owner, name, dest_user):
    """
    Scenario unsharing form page.
    """
    if owner != current_user.username:
        return make_response("Can't unshare scenarios that aren't yours.", 401)
    
    owner_username = owner
    owner_user = models.load_user(owner_username)
    
    matching_shares = []
    for share in owner_user.shared_scenarios:
        if share['dest_username'] == dest_user and share['ag_name'] == name:
            matching_shares.append(share)
    
    if not matching_shares:
        return make_response("That scenario is not shared with this user.", 404)
    
    form = forms.ConfirmForm()
    
    if form.validate_on_submit():
        for share in matching_shares:
            owner_user.shared_scenarios.remove(share)
        owner_user.store()
        couchdb_manager.sync(app)
        flash('Scenario successfully unshared.', 'success')
        return redirect(url_for('web_scenario_share', owner=owner, name=name))
    return render_template('scenario_unshare.html', form=form, name=name,
                           owner=owner_username, dest_user=dest_user)

@app.route('/interactive/attackgraphs/<owner>/<name>/add/', methods=['GET', 'POST'])
@login_required
def web_create_generation_task(owner, name):
    """
    Generation task creation form page.
    """
    if owner != current_user.username:
        scenario_name = get_owned_ag_name(owner, name)
        if scenario_name not in current_user.available_scenarios():
            return make_response('This scenario (if it even exists) has not ' \
                                 'been shared with you.', 401)
        owner_username = owner
    else:
        owner_username = current_user.username
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
                                  username=owner_username)
        
        if not ret:
            if adg:
                task_name = 'attack dependency graph'
            else:
                task_name = 'attack state graph of depth %i' % depth
            if not ret:
                flash('Queued generation of %s %s' % (name, task_name), 'success')
            return redirect(url_for('web_scenario_detail', owner=owner, name=name)) # TODO
        else:
            flash(ret[0], 'error')
            return render_template('task_form.html', form=form, name=name)
    return render_template('task_form.html', form=form, name=name, owner=owner_username)

@app.route('/interactive/attackgraphs/<owner>/<name>/delete/', methods=['GET','POST'])
@login_required
def web_scenario_delete(owner, name):
    """
    Attack graph scenario deletion.
    """
    if owner != current_user.username:
        return make_response('You may not delete scenarios that do not belong' \
                             'to you.', 401)
    else:
        owner_username = current_user.username
        
    form = forms.ConfirmForm(request.form)
    # TODO: better error handling.
    if form.validate_on_submit():
        delete_scenario(name, username=owner_username)
        flash('Deleted scenario %s' % (name,), 'success')
        return redirect(url_for('web_landing'))
    return render_template('scenario_delete.html', form=form, name=name, owner=owner_username)

@app.route('/interactive/attackgraphs/<owner>/<name>/<task>/restart/', methods=['GET','POST'])
@login_required
def web_task_restart(owner, name, task):
    """
    Attack graph task restart.
    """
    if owner != current_user.username:
        scenario_name = get_owned_ag_name(owner, name)
        if scenario_name not in current_user.available_scenarios():
            return make_response('This scenario (if it even exists) has not ' \
                                 'been shared with you.', 401)
        owner_username = owner
    else:
        owner_username = current_user.username
        
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
                    username=owner_username)
        ret = new_generation_task(name, depth=depth, adg=adg,
                                  username=owner_username)
        if not ret:
            flash('Restarted generation of %s %s' % (name, task_name), 'success')
            return redirect(url_for('web_scenario_detail', owner=owner, name=name))
        else:
            return make_response(*ret)
    return render_template('task_restart.html', form=form, name=name,
                           task=task_name, owner=owner_username)

@app.route('/interactive/attackgraphs/<owner>/<name>/<task>/delete/', methods=['GET','POST'])
@login_required
def web_task_delete(owner, name, task):
    """
    Attack graph task delete.
    """
    if owner != current_user.username:
        scenario_name = get_owned_ag_name(owner, name)
        if scenario_name not in current_user.available_scenarios():
            return make_response('This scenario (if it even exists) has not ' \
                                 'been shared with you.', 401)
        owner_username = owner
    else:
        owner_username = current_user.username
        
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
        delete_task(name, depth=depth, adg=adg, username=owner_username)
        flash('Deleted %s %s' % (name, task_name), 'success')
        return redirect(url_for('web_scenario_detail', owner=owner, name=name))
    return render_template('task_delete.html', form=form, name=name,
                           task=task_name, owner=owner_username)
