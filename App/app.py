from flask import Flask, render_template , url_for , redirect , request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user , LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField , EmailField , RadioField , SelectField
from wtforms.validators import InputRequired, Length, ValidationError 
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config["SECRET_KEY"] = "thisisasecretkey"



login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Creating model table for our CRUD database
class User(db.Model , UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    gradeaverage = db.Column(db.String(20), nullable=False)
    courses = db.Column(db.String(20), nullable=False)


    
    def __init__(self, username, password, email , status, gradeaverage , courses):

        self.username = username
        self.password = password
        self.email = email
        self.status = status
        self.gradeaverage = gradeaverage
        self.courses= courses

grade_choices = [('A','A') , ('B','B'), ('C','C'), ('D','D'), ('D','E')]
courses_choices = [('Bsc','Bsc') , ('B ed','B ed'), ('BA','BA'), ('BCOM','BCom'), ('BTech','Btech')]

#registerform
class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Username'})

    password = PasswordField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Password'})

    email = EmailField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Email'})

    gradeaverage = SelectField(u'grade', choices=grade_choices)

    status = StringField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'value':'Pending'})


    courses = SelectField(u'grade', choices=courses_choices)



  

    submit = SubmitField('Register')


    def validate_email(self, email):
        existing_user_email = User.query.filter_by(
            email=email.data).first()

        if existing_user_email:
            raise ValidationError(
                "That email already exists.")


#LoginForm
class LoginForm(FlaskForm):

    password = PasswordField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Password'})

    email = EmailField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Email'})

    submit = SubmitField('Login')


#adminform
class AdminForm(FlaskForm):

    password = PasswordField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Password'})

    email = EmailField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'Email'})

    code = PasswordField(validators=[InputRequired(),Length(min=4 , max=20)], render_kw={'placeholder':'code'})

    submit = SubmitField('Admin login')

status_choices = [('Accepted','Accept') , ('Declined','Decline')]

class StatusForm(FlaskForm):

    status = SelectField(u'status', choices=status_choices)
    submit = SubmitField('Update')


#this our interface

@app.route('/home')
def home():
    return render_template("index.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/course')
def course():
    return render_template("courses.html")



@app.route('/dashboard' , methods=["GET", "POST"])
def dashboard():
    return render_template("dashboard.html", 
    username = current_user.username,
    email = current_user.email,
    courses = current_user.courses,
    gradeaverage = current_user.gradeaverage,
    status = current_user.status)


@app.route('/adminview' , methods=["GET", "POST"])
def adminview():
    all_data = User.query.all()

    return render_template("marks.html", User = all_data)



#this our forms

@app.route('/login' , methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
       
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for("dashboard"))

    return render_template("login.html" , form=form)



@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, email=form.email.data, password=hashed_password, 
        gradeaverage=form.gradeaverage.data , status=form.status.data , courses=form.courses.data )

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register.html" , form=form)



@app.route('/admin' , methods=["GET", "POST"])
def admin():
    form = AdminForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
       
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                
                login_user(user)
                return redirect(url_for("adminview"))

    return render_template("admin.html" , form=form)





#this is our logout fuctions 

@app.route('/logout' , methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))
    
@app.route('/adminlogout' , methods=["GET", "POST"])
@login_required
def adminlogout():
    logout_user()
    return redirect(url_for("admin"))






#this is our accpect route
@app.route('/action/<int:id>', methods = ['GET', 'POST'])
def actions(id):
    form=StatusForm()

    student_to_update = User.query.get_or_404(id)
    if request.method == "POST":

        student_to_update.status = request.form['status']
        db.session.commit()

        return redirect(url_for('adminview'))


    return render_template('update.html' , form=form)




if __name__ == "__main__":
    app.run(debug=True)