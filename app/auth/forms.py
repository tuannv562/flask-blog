from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import Required, Email, Length, Regexp, EqualTo
from wtforms import ValidationError
from ..models import User


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
                        Required(), Length(1, 64), Email()])
    password = PasswordField('Password', validators=[Required()])
    remember_me = BooleanField('Keep me logged in')
    submit = SubmitField('Log In')


class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
                        Required(), Length(1, 64), Email()])
    username = StringField('Username', validators=[Required(), Length(1, 64), Regexp(
        '^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Usernames must have only letters, numbers, dots or underscores')])
    password = PasswordField('Password', validators=[Required(), EqualTo(
        'password2', message='Passwords must match!')])
    password2 = PasswordField('Confirm password', validators=[Required()])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already in use')


class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old password', validators=[Required()])
    new_password = PasswordField('New password', validators=[Required(), EqualTo(
        'confirm_new_password', message='Passwords must match')])
    confirm_new_password = PasswordField(
        'Confirm new password', validators=[Required()])
    submit = SubmitField('Submit')


class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[
                        Required(), Email(), Length(1, 64)])
    submit = SubmitField('Submit')


class PasswordResetForm(FlaskForm):
    email = StringField('Email', validators=[
                        Required(), Email(), Length(1, 64)])
    new_password = PasswordField('New password', validators=[Required(), EqualTo(
        'confirm_new_password', message='Password must match')])
    confirm_new_password = PasswordField(
        'Confirm new password', validators=[Required()])
    submit = SubmitField('Submit')


class ChangeEmailForm(FlaskForm):
    email = StringField('New email', validators=[
                        Required(), Email(), Length(1, 64)])
    password = PasswordField('Password', validators=[Required()])
    submit = SubmitField('Update email address')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')
