from functools import wraps

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
ckeditor = CKEditor(app)
Bootstrap(app)

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(
    app,
    size=100,
    rating="g",
    default='retro',
    force_default=False,
    force_lower=False,
    use_ssl=False,
    base_url=None
)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(400), nullable=False)
    name = db.Column(db.String(400), nullable=False)
    posts = relationship('BlogPost', back_populates='author')
    comments = relationship('Comment', back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship('User', back_populates='posts')
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship('Comment', back_populates='parent_post')
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    text = db.Column(db.String(1000), nullable=False)
    comment_author = relationship('User', back_populates='comments')
    parent_post = relationship('BlogPost', back_populates='comments')
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))


# db.create_all()


def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.id == 1:
            return function(*args, **kwargs)
        else:
            abort(403)

    wrapper_function.__name__ = function.__name__
    return wrapper_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


# noinspection PyArgumentList
@app.route('/register', methods=['POST', 'GET'])
def register():
    reg_form = RegisterForm()
    user_emails = [user.email for user in User.query.all()]
    if reg_form.validate_on_submit():
        name = reg_form.name.data
        email = reg_form.email.data
        password = generate_password_hash(password=reg_form.password.data, method='pbkdf2:sha256', salt_length=8)
        if email in user_emails:
            flash("You've created an account with this email already, please login instead.")
            return redirect('login')
        new_user = User(
            name=name,
            email=email,
            password=password
        )
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=reg_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    login_form = LoginForm()
    user_emails = [user.email for user in User.query.all()]
    if login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()
        if login_form.email.data not in user_emails:
            flash('This email does not exist, please try again.')
            return redirect('login')
        if check_password_hash(user.password, login_form.password.data):
            login_user(user)
            return redirect(url_for('get_all_posts'))
        else:
            flash('Password is incorrect, please try again.')
            return redirect('login')
    return render_template("login.html", form=login_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    comment_form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    comments = Comment.query.all()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash('You need to login or register to comment.')
            return redirect(url_for('login'))
        user = User.query.filter_by(id=current_user.id).first()
        post = BlogPost.query.filter_by(id=post_id).first()
        text = comment_form.comment.data
        new_comment = Comment(
            author_id=user.id,
            text=text,
            post_id=post.id,
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for('show_post', post_id=post_id))
    return render_template("post.html", post=requested_post, form=comment_form, comments=comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
