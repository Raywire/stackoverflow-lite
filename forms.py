from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class SignupForm(FlaskForm):
    first_name = StringField('First name', validators=[DataRequired("Please enter your first name.")])
    last_name = StringField('Last name', validators=[DataRequired("Please enter your last name.")])
    email = StringField('Email', validators=[DataRequired("Please enter your email address."), Email("Please enter a valid email address.")])
    password = PasswordField('Password', validators=[DataRequired("Please enter a password."), Length(min=6, message="Passwords must be 6 characters or more.")])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired("Passwords must match"), EqualTo('password')])
    submit = SubmitField('Sign up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired("Please enter your email address."), Email("Please enter a valid email address.")])
    password = PasswordField('Password', validators=[DataRequired("Please enter a password."), Length(min=1, message="Enter a valid password")])
    submit = SubmitField("Sign in")

class QuestionForm(FlaskForm):
    subject = StringField('Title', validators=[DataRequired("Please enter a title.")])
    message = TextAreaField('Body', validators=[DataRequired("Please enter your question.")])
    submit = SubmitField("Post Your Question")

class ReplyForm(FlaskForm):
    message = TextAreaField('Body', validators=[DataRequired("Please enter your answer.")])
    submit = SubmitField("Post Your Answer")

class ResetPasswordForm(FlaskForm):
    old_password = PasswordField('Current Password', validators=[DataRequired("Please enter a password."), Length(min=1, message="Enter a valid password.")])
    password = PasswordField('New Password', validators=[DataRequired("Please enter a password."), Length(min=6, message="Passwords must be 6 characters or more.")])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired("Passwords must match"), EqualTo('password')])
    submit = SubmitField("Reset Password")

class UpdateAccountForm(FlaskForm):
    first_name = StringField('First name', validators=[DataRequired("Please enter your first name.")])
    last_name = StringField('Last name', validators=[DataRequired("Please enter your last name.")])
    submit = SubmitField('Update')
