from flask import Flask, render_template, request, session, redirect, url_for, jsonify, make_response, flash
from models import db, User, Question, Answer
from forms import SignupForm, LoginForm, QuestionForm, ReplyForm, ResetPasswordForm, UpdateAccountForm
from flask_humanize import Humanize
from werkzeug import generate_password_hash, check_password_hash
from functools import wraps

import datetime
import uuid
import jwt

app = Flask(__name__)
humanize = Humanize(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:@Hortec9016@localhost/stackoverflowlite'
db.init_app(app)

app.secret_key = "d01815253d8243a221d12a681589155e"

@app.route("/")
def index():
    page = request.args.get('page', 1, type = int)
    questions = Question.query.order_by(Question.date_posted.desc()).paginate(page = page, per_page = 10)
    answers = Answer.query.all()
    return render_template("index.html", questions = questions, answers = answers)

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/signup", methods=['GET', 'POST'])
def signup():
    if 'email' in session:
        return redirect(url_for('index'))
    form = SignupForm()

    if request.method == 'POST':
        if form.validate() == False:
            return render_template('signup.html', form=form)
        else:
            #check if email exists
            user = User.query.filter_by(email = form.email.data).first()
            if user is not None:
                flash(f'Account for {form.email.data} already exists', 'warning')
                return render_template("signup.html", form=form)
            else:
                newuser = User(form.first_name.data, form.last_name.data, form.email.data, form.password.data, admin = False, public_id = str(uuid.uuid4()))
                db.session.add(newuser)
                db.session.commit()

                session['email'] = newuser.email
                session['public_id'] = newuser.public_id
                flash(f'Account created for {form.email.data}', 'success')
                return redirect(url_for('index'))
    elif request.method == 'GET':
        return render_template("signup.html", form=form)

@app.route("/login", methods=["GET", "POST"])
def login():
    if 'email' in session:
        return redirect(url_for('index'))
    form = LoginForm()

    if request.method == "POST":
        if form.validate() == False:
            return render_template("login.html", form=form)
        else:
            email = form.email.data
            password = form.password.data
            user = User.query.filter_by(email=email).first()
            if user is not None and user.check_password(password):
                session['email'] = form.email.data
                session['public_id'] = user.public_id
                flash(f'Login successful', 'info')
                return redirect(url_for('index'))
            else:
                flash(f'Check your email or password', 'danger')
                return redirect(url_for('login'))
    elif request.method == "GET":
        return render_template('login.html', form=form)


@app.route("/logout")
def logout():
  session.pop('email', None)
  return redirect(url_for('index'))

@app.route("/questions/ask", methods=["GET", "POST"])
def new_question():
    if 'email' not in session:
        return redirect(url_for('login'))
    form = QuestionForm()

    if request.method == 'POST':
        if form.validate() == False:
            return render_template('new_question.html', form=form)
        else:
            user = User.query.filter_by(email = session['email']).first()
            newquestion = Question(form.subject.data, form.message.data, date_posted = datetime.datetime.utcnow(), last_updated = datetime.datetime.utcnow(), starter = user.uid , views = 0)
            db.session.add(newquestion)
            db.session.commit()
            flash(f'Question has been posted', 'info')

            return redirect(url_for('index'))
    elif request.method == 'GET':
        return render_template("new_question.html", form=form)

@app.route("/question/<int:qid>")
def view_question(qid):
    if 'email' not in session:
        return redirect(url_for('login'))

    answers = Answer.query.filter_by(question_tag = qid).order_by(Answer.date_posted.desc())
    question = Question.query.filter_by(qid = qid).first()
    #session.query(User).filter(User.name.like('%ed')).count()
    count = Answer.query.filter_by(question_tag = qid).count()

    user = User.query.filter_by(email = session['email']).first()
    session_key = [];
    if question.qid not in session_key:
        question.views += 1
        db.session.commit()
        session_key.append(question.qid)
    return render_template("view_question.html", question = question, user = user, answers = answers, count = count)

@app.route("/questions/user/<public_id>")
def user_questions(public_id):
    page = request.args.get('page', 1, type = int)
    user = User.query.filter_by(public_id=public_id).first_or_404()
    fullname = user.firstname + ' ' + user.lastname
    questions = Question.query.filter_by(starter=user.uid).order_by(Question.date_posted.desc()).paginate(page = page, per_page = 10)
    answers = Answer.query.all()
    return render_template("user_questions.html", questions = questions, answers = answers, fullname = fullname)

@app.route("/questions/<int:qid>/reply", methods=["GET", "POST"])
def reply_question(qid):
    if 'email' not in session:
        return redirect(url_for('login'))

    form = ReplyForm()
    question = Question.query.filter_by(qid=qid).first()

    if request.method == 'POST':
        if form.validate() == False:
            return render_template('reply_question.html', form=form)
        else:
            user = User.query.filter_by(email = session['email']).first()
            newanswer = Answer(form.message.data, question_tag = qid, date_posted = datetime.datetime.utcnow(), updated_at = datetime.datetime.utcnow(), answered_by = user.uid)
            db.session.add(newanswer)
            db.session.commit()

            return redirect(url_for('view_question', qid = qid))
    elif request.method == 'GET':
        return render_template("reply_question.html", question = question, form = form)




@app.route("/question/<int:qid>/delete")
def delete_question(qid):
    question = Question.query.filter_by(qid=qid).first()
    db.session.delete(question)
    db.session.commit()
    flash(f'Question has been deleted', 'success')

    return redirect(url_for('index'))


@app.route("/settings/password", methods = ['GET', 'POST'])
def reset_password():
    if 'email' not in session:
        return redirect(url_for('login'))
    form = ResetPasswordForm()
    if request.method == "POST":
        if form.validate() == False:
            return render_template("reset_password.html", form=form)
        else:
            old_password = form.old_password.data
            password = form.password.data
            user = User.query.filter_by(email=session['email']).first()
            if user is not None and user.check_password(old_password):
                user.pwdhash = generate_password_hash(password)
                db.session.commit()
                flash(f'Password reset successful', 'success')
                return render_template('reset_password.html', form=form)
            else:
                flash(f'Current password is incorrect', 'danger')
                return render_template('reset_password.html', form=form)
    elif request.method == "GET":
        return render_template('reset_password.html', form=form)

@app.route("/settings/account", methods = ['GET', 'POST'])
def user_account():
    if 'email' not in session:
        return redirect(url_for('login'))

    form = UpdateAccountForm()
    user = User.query.filter_by(email=session['email']).first()

    if request.method == "POST":
        if form.validate() == False:
            return render_template('account.html', user = user, form = form)
        else:
            user.firstname = form.first_name.data
            user.lastname = form.last_name.data
            db.session.commit()
            flash('Your account has been updated', 'success')
            return redirect(url_for('user_account'))

    elif request.method == "GET":
        form.first_name.data = user.firstname
        form.last_name.data = user.lastname
        return render_template('account.html', user = user, form = form)



########## API   #############################################################################################################################################
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route("/auth/getusers", methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['firstname'] = user.firstname
        user_data['lastname'] = user.lastname
        user_data['email'] = user.email
        user_data['password'] = user.pwdhash
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route("/auth/getuser/<public_id>", methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['firstname'] = user.firstname
    user_data['lastname'] = user.lastname
    user_data['email'] = user.email
    user_data['password'] = user.pwdhash
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route("/auth/signup", methods=['POST'])
@token_required
def create_user(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function'})

    data = request.get_json()

    newuser = User(public_id = str(uuid.uuid4()) , firstname=data['firstname'], lastname = data['lastname'], email = data['email'], password = data['password'], admin = False)
    db.session.add(newuser)
    db.session.commit()
    return jsonify({'message':'new user created'})

@app.route("/auth/promoteuser/<public_id>", methods=['PUT'])
@token_required
def promote_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted'})

@app.route("/auth/deleteuser/<public_id>", methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted'})

@app.route('/auth/login')
def auth_login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.pwdhash, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/questions', methods=['GET'])
def get_all_questions():
    questions = Question.query.order_by(Question.date_posted.desc())

    output = []

    for question in questions:
        question_data = {}
        question_data['qid'] = question.qid
        question_data['title'] = question.title
        question_data['body'] = question.body
        question_data['date_posted'] = question.date_posted
        question_data['last_updated'] = question.last_updated
        question_data['starter'] = question.starter
        question_data['views'] = question.views
        output.append(question_data)

    return jsonify({'questions' : output})

@app.route('/questions/<questionId>', methods=['GET'])
def get_one_question(questionId):
    question = Question.query.filter_by(qid = questionId).first()

    if not question:
        return jsonify({'message' : 'Question not found'})

    question_data = {}
    question_data['qid'] = question.qid
    question_data['title'] = question.title
    question_data['body'] = question.body
    question_data['date_posted'] = question.date_posted
    question_data['last_updated'] = question.last_updated
    question_data['starter'] = question.starter
    question_data['views'] = question.views

    return jsonify({'question' : question_data})

@app.route('/questions', methods=['POST'])
@token_required
def post_question(current_user):
    data = request.get_json()

    newquestion = Question(title = data['title'], body = data['body'], date_posted = datetime.datetime.utcnow(), last_updated = datetime.datetime.utcnow(), starter = current_user.uid , views = 0)
    db.session.add(newquestion)
    db.session.commit()

    return jsonify({'message': 'Question has been posted'})

@app.route('/questions/<questionId>', methods=['DELETE'])
@token_required
def delete_question1(current_user, questionId):
    question = Question.query.filter_by(qid = questionId).first()

    if not question:
        return jsonify({'message' : 'Question not found'})

    db.session.delete(question)
    db.session.commit()

    return jsonify({'message' : 'Question has been deleted'})



if __name__ == "__main__":
    app.run(debug=True)
