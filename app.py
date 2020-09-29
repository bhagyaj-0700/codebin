from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissupposedtobesecret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_DEBUG'] = False
app.config['MAIL_USERNAME'] = 'mail.deltawing@gmail.com'
app.config['MAIL_PASSWORD'] ='bhagyaj2003'
app.config['MAIL_DEFAULT_SENDER'] = 'mail.deltawing@gmail.com'
app.config['MAIL_MAX_EMAILS'] = 100
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_ASCII_ATTACHMENTS'] = False

s = URLSafeTimedSerializer('Thisisfuckingsecretgetlostbitch!')

bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    verified = db.Column(db.Boolean, server_default='f', default=False)
    type = db.Column(db.String(25), default = 'member')

class Code(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(80))
    code = db.Column(db.String())
    category = db.Column(db.String(50))

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, unique=True)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

class UserView(ModelView):
    column_exclude_list = ['password']
    form_excluded_columns = ['password']

admin = Admin(app)
admin.add_view(UserView(User, db.session))
admin.add_view(ModelView(Code, db.session))
admin.add_view(ModelView(Category, db.session))


@app.route('/')
def index():
    options = ['category']
    optionsdb = Category.query.all()
    for opt in optionsdb:
        options.append(opt.title)
    codes = []
    codes = Code.query.all()
    return render_template('index.html', options=options, codes = codes)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('index'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    exist = db.engine.execute("SELECT * FROM User WHERE username = ? or email = ?", (form.username.data,form.email.data)).first()
    if exist:
        flash(message='The username or password already exists!', category='error')
        return redirect(url_for('signup'))
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, verified=False)
        db.session.add(new_user)
        db.session.commit()
        #send email
        email = form.email.data
        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm Email', sender='mail.deltawing@gmail.com', recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = 'Please verify your email using this link {}'.format(link)
        mail.send(msg)
        #email sent
        flash('Account has been successfully created', category = 'success')
        return redirect(url_for('login'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        user = User.query.filter_by(email=email).first()
        user.verified = True
        db.session.commit()
    except SignatureExpired:
        return '<h1>The token is expired!</h1>'
    flash('Email has been successfully verified!')
    return redirect(url_for('login'))



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/submit/', methods=['GET', 'POST'])
#@login_required
def submit():
    if request.method == 'GET':
        options = []
        optionsdb = Category.query.all()
        for opt in optionsdb:
            options.append(opt.title)
        return render_template('submit.html', options=options)
    if request.method == 'POST':
        title = request.form['title']
        code = request.form['code']
        category = request.form['category']
        code = Code(title=title, code=code, category=category)
        db.session.add(code)
        db.session.commit()
        return '<h1>YOUR CODE HAS BEEN SUCCESSFULLY SUBMITTED</h1>'


@app.route('/category/add/<name>')
def add_category(name):
    categ = Category(title=name)
    db.session.add(categ)
    db.session.commit()
    return f'<h1>{name} has been added to database</h1>'

@app.route('/category/remove/<name>')
def remove_category(name):
    categ = Category.query.filter_by(title=name).first()
    db.session.delete(categ)
    db.session.commit()

@app.route('/view/<id>')
def view(id):
    options = ['category']
    optionsdb = Category.query.all()
    for opt in optionsdb:
        options.append(opt.title)

    code_query = Code.query.filter_by(id=id).first()
    return render_template('view.html',options=options, title=code_query.title, code=code_query.code, category = code_query.category)

@app.route('/search/')
def search():
    options = ['category']
    optionsdb = Category.query.all()
    for opt in optionsdb:
        options.append(opt.title)
    keywords = request.args.get('words').split(' ')
    codes = Code.query.all()
    results = []
    for code in codes:
        for keyword in keywords:
            if keyword in code.title:
                if request.args.get('filter') == "category":
                    results.append(code)
                elif request.args.get('filter') == code.category:
                    results.append(code)
                break
    return render_template('index.html', codes=results, options=options)



if __name__ == '__main__':
    app.run(debug=True)
