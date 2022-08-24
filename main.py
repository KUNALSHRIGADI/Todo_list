from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from forms import RegisterForm, LoginForm
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = "qwertyuiop"
bootstrap = Bootstrap(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100), unique=True)
    todo = relationship("Todo", back_populates="")


# db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    todo = db.Column(db.String(255), nullable=False)


# db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)

    return decorated_function


@app.route('/', methods=["POST", "GET"])
@login_required
def home():
    requested_todo = Todo.query.all()
    if request.method == "POST":
        todo = request.form.get('todo')
        entry = Todo(todo=todo)
        db.session.add(entry)
        db.session.commit()
        return redirect(url_for("home"))
    return render_template("index.html", todos=requested_todo, name=current_user)


# @app.route('/', methods=["POST", "GET"])
# def home():
#     Todo.query.delete()
#     db.session.commit()
#
#     return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    # if form.validate_on_submit():
    # hashed_password = generate_password_hash(form.password.data, method="sha256")
    # new_user = User(email=form.email.data, password=hashed_password, name=form.username.data)
    # db.session.add(new_user)
    # db.session.commit()
    # login_user(new_user)
    # return redirect(url_for("home"))
    if form.validate_on_submit():
        if User.query.filter_by(email=form.email.data).first():
            print(User.query.filter_by(email=form.email.data).first())
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("home"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    # if form.validate_on_submit():
    #     # return "<h1>" + form.username.data + " " + form.password.data + "<h1>"
    #     user = User.query.filter_by(name=form.username.data).first()
    #     if user:
    #         if check_password_hash(user.password, form.password.data):
    #             login_user(user, remember=form.remember.data)
    #             return redirect(url_for("home"))
    #     else:
    #         return "<h1> Invalid username and password </h1>"
    if form.validate_on_submit():
        name = form.username.data
        password = form.password.data

        user = User.query.filter_by(name=name).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))
    return render_template("login.html", form=form, name=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template("logout.html")


# db.session.close_all()


if __name__ == '__main__':
    app.run(debug=True)
