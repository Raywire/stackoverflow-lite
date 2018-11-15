from flask_sqlalchemy import SQLAlchemy
from werkzeug import generate_password_hash, check_password_hash

import datetime

db = SQLAlchemy()

class User(db.Model):
  __tablename__ = 'users'
  uid = db.Column(db.Integer, primary_key = True)
  firstname = db.Column(db.String(100))
  lastname = db.Column(db.String(100))
  email = db.Column(db.String(120), unique=True)
  pwdhash = db.Column(db.String(54))

  def __init__(self, firstname, lastname, email, password):
    self.firstname = firstname.title()
    self.lastname = lastname.title()
    self.email = email.lower()
    self.set_password(password)

  def set_password(self, password):
    self.pwdhash = generate_password_hash(password)

  def check_password(self, password):
    return check_password_hash(self.pwdhash, password)

class Question(db.Model):
    __tablename__ = 'questions'
    qid = db.Column(db.Integer, primary_key = True)
    title = db.Column(db.String(80), nullable = False)
    body = db.Column(db.Text, nullable = False)
    date_posted = db.Column(db.DateTime, nullable = False, default=datetime.datetime.utcnow())
    last_updated = db.Column(db.DateTime, nullable = False, default=datetime.datetime.utcnow())
    #starter = db.Column(db.Integer,nullable=False, db.ForeignKey('uid.id'))#ForeignKey to reference uid in users table
    #user = db.relationship('User', backref=db.backref('questions', lazy=True))
    starter = db.Column(db.Integer)
    views = db.Column(db.Integer, default=0)
    #starter = db.Column(db.Integer, db.ForeignKey('user.uid'))
    #user = db.relationship("User", backref = db.backref("user", uselist=False))
    def __init__(self, title, body, date_posted, last_updated, starter, views):
        self.title = title.title()
        self.body = body.title()
        self.date_posted = date_posted
        self.last_updated = last_updated
        self.starter = starter
        self.views = views
'''
class Answer(db.Model):
    __tablename__ = 'answers'
'''
