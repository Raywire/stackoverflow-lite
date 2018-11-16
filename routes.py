from flask import Flask, render_template, request, session, redirect, url_for
from models import db, User, Question, Answer
from forms import SignupForm, LoginForm, QuestionForm, ReplyForm

import datetime

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:@Hortec9016@localhost/stackoverflowlite'
db.init_app(app)

app.secret_key = "development-key"

@app.route("/")
def index():
    questions = Question.query.all()
    return render_template("index.html", questions=questions)

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
            newuser = User(form.first_name.data, form.last_name.data, form.email.data, form.password.data)
            db.session.add(newuser)
            db.session.commit()

            session['email'] = newuser.email
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
                return redirect(url_for('index'))
            else:
                return redirect(url_for('login'))
    elif request.method == "GET":
        return render_template('login.html', form=form)


@app.route("/logout")
def logout():
  session.pop('email', None)
  return redirect(url_for('index'))

@app.route("/new_question", methods=["GET", "POST"])
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

            return redirect(url_for('index'))
    elif request.method == 'GET':
        return render_template("new_question.html", form=form)

@app.route("/questions/<int:qid>")
def view_question(qid):
    answers = Answer.query.filter_by(question_tag = qid)
    question = Question.query.filter_by(qid = qid).first()
    user = User.query.filter_by(email = session['email']).first()
    session_key = [];
    if question.qid not in session_key:
        question.views += 1
        db.session.commit()
        session_key.append(question.qid)
    return render_template("view_question.html", question = question, user = user, answers = answers)

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

    return redirect(url_for('index'))


if __name__ == "__main__":
    app.run(debug=True)
