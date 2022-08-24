from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length, Email


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[InputRequired(), Email(message="Invalid email"), Length(max=50)])
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=80)])
    # submit = SubmitField("Sign Me Up!")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField("Remember Me")
    # submit = SubmitField("Let Me In!")
