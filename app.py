from flask import Flask, render_template, url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,login_required,login_user,current_user, logout_user
import click
from flask.cli import with_appcontext
from wtforms import StringField, PasswordField, EmailField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_wtf import FlaskForm
from flask_bcrypt import Bcrypt

app=Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///db.db'

app.config['SECRET_KEY'] = 'PLATANO'

db=SQLAlchemy(app)

bcrypt=Bcrypt(app)

login_manager=LoginManager()

login_manager.init_app(app)

login_manager.login_view='login'

@login_manager.user_loader
def load_user(user_id):
    return user.query.get(int(user_id))

class user(db.Model):
   id = db.Column(db.Integer, autoincrement =True, primary_key = True)
   email= db.Column(db.String(100),nullable = False)
   password = db.Column(db.String(50),nullable = False)  
   username=db.Column(db.String(50),nullable = False,unique = True) 

class RegisterForm(FlaskForm):
    email = EmailField('email', validators=[InputRequired()], render_kw={"placeholder": "Email"})
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=12)], render_kw={"placeholder": "Senha"})
    username = StringField('username', validators=[InputRequired()], render_kw={"placeholder": "Usuario"})
    submit = SubmitField('Login')
    def validate_user(self,username):
        existing_user_username= user.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Esse nome de usuário já existe")
        
class LoginForm(FlaskForm):
    email=EmailField('email',validators=[InputRequired()], render_kw={"placeholder": "Email"})
    password=PasswordField('password',validators=[InputRequired(), Length(min=8, max=12)], render_kw={"placeholder": "Senha"})
    submit=SubmitField("signup")

@app.route('/login', methods=['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        Cuser=user.query.filter_by(email=form.email.data).first()
        if Cuser:
            if bcrypt.check_password_hash(Cuser.password,form.password.data):
                login_user(Cuser)
                return redirect(url_for('home'))
    return render_template('login.html',form=form)

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/',methods=['GET','POST'])
def sign():
    form=RegisterForm()
    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_user=user(email=form.email.data, password=hashed_password, username=form.username.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('sign.html', form=form)

if __name__=='__main__':
    app.run(debug=True)

@click.command(name='create')
@with_appcontext
def create():
    db.create_all()
app.cli.add_command(create)
