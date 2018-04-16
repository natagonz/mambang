from flask import Flask,render_template,flash, url_for, redirect, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField ,TextAreaField
from wtforms.validators import InputRequired, EqualTo, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from flask_login import LoginManager , UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
from functools import wraps
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer,SignatureExpired
from flask_uploads import UploadSet, IMAGES, configure_uploads
from flask_wtf.file import FileField, FileAllowed, FileRequired

app = Flask(__name__)
app.config["SECRET_KEY"] = "Rahasia123"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:bali2017@localhost/ems"
db = SQLAlchemy(app)


#migrate database
migrate = Migrate(app, db)
manager = Manager(app)
manager.add_command('db',MigrateCommand)

#login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "Login"

#fungsi mail
app.config.from_pyfile("config.cfg") 
mail = Mail(app)
s = URLSafeTimedSerializer("secret")

#fungsi Upload
#mengatur image
images = UploadSet("images",IMAGES)
app.config["UPLOADED_IMAGES_DEST"] = "static/img/profile/"
app.config["UPLOADED_IMAGES_URL"] = "http://mambangsehat.com/static/img/profile/"
configure_uploads(app,images)




class User(db.Model):
	id = db.Column(db.Integer,primary_key=True)
	username = db.Column(db.String(50),unique=True)
	full_name = db.Column(db.String(100))
	phone = db.Column(db.String(100))
	email = db.Column(db.String(100),unique=True)
	password = db.Column(db.String(150))
	address = db.Column(db.String(100))
	image_name = db.Column(db.String(200))
	image_url = db.Column(db.String(200))
	role = db.Column(db.String(50))


	def is_active(self):
		return True

	def get_id(self):
		return self.id

	def is_authenticated(self):
		return self.authenticated

	def is_anonymous(self):
		return False



class Patient(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	name = db.Column(db.String(50))
	phone = db.Column(db.String(50))
	birthdate = db.Column(db.String(50))
	address = db.Column(db.String(50))
	description = db.Column(db.String(225))
	image_name = db.Column(db.String(200))
	image_url = db.Column(db.String(200))
	reports = db.relationship("Report", backref="owner", lazy="dynamic")

class Report(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	title = db.Column(db.String(100))
	report = db.Column(db.String(225))
	comment = db.Column(db.String(225))
	image_name = db.Column(db.String(200))
	image_url = db.Column(db.String(200))
	date = db.Column(db.DateTime, default=db.func.current_timestamp())
	doctor = db.Column(db.String(50))
	owner_id = db.Column(db.Integer, db.ForeignKey("patient.id"))





###########################################################
########## 								     ##############
##########        DECORATOR			         ##############
########## 									 ##############
########## 									 ##############
###########################################################


#login manager
@login_manager.user_loader
def user_loader(user_id):
	return User.query.get(int(user_id))


#mengatur role 
def roles_required(role="ANY"):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if ((current_user.role != role) and (role != "ANY")):
                return "no access"
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper




###########################################################
########## 								     ##############
##########        WTF FORM CLASS             ##############
########## 									 ##############
########## 									 ##############
###########################################################


class UserRegisterForm(FlaskForm):
	username = StringField("Username",validators=[InputRequired(),Length(min=2,max=50)])
	full_name = StringField("Full Name",validators=[InputRequired(),Length(min=2,max=100)])
	phone = StringField("Phone",validators=[InputRequired(),Length(min=2,max=100)])
	email = StringField("Email",validators=[InputRequired(),Length(min=3,max=100),Email(message="Invalid Email")])
	password = PasswordField("Password",validators=[InputRequired(),EqualTo("confirm",message="Password not Match")])
	confirm = PasswordField("Confirm Password")
	address = StringField("Address",validators=[Length(max=200)])
	image = FileField("Upload Image",validators=[FileAllowed(images,"Images only")])
	

class UserEditForm(FlaskForm):
	username = StringField("Username",validators=[InputRequired(),Length(min=2,max=50)])
	full_name = StringField("Full Name",validators=[InputRequired(),Length(min=2,max=100)])
	phone = StringField("Phone",validators=[InputRequired(),Length(min=2,max=100)])
	email = StringField("Email",validators=[InputRequired(),Length(min=3,max=100),Email(message="Invalid Email")])
	address = StringField("Address",validators=[Length(max=200)])


class UserUploadPhoto(FlaskForm):
	image = FileField("Upload Image",validators=[FileAllowed(images,"Images only")])
	
	

class UserLoginForm(FlaskForm):
	username = StringField("Username",validators=[InputRequired(),Length(min=5,max=50)])
	password = PasswordField("Password",validators=[InputRequired()])


class AddPatientForm(FlaskForm):
	name = StringField("Name",validators=[Length(max=50)])
	phone = StringField("Phone",validators=[Length(max=50)])
	birthdate = StringField("Birthdate",validators=[Length(max=50)])
	address = StringField("Address",validators=[Length(max=50)])
	description = TextAreaField("Description",validators=[Length(max=225)])
	image = FileField("Upload Image",validators=[FileAllowed(images,"Images only")])

class ReportForm(FlaskForm):
	title = StringField("Title",validators=[InputRequired(),Length(max=100)])
	report = TextAreaField("Report",validators=[InputRequired()])
	comment = TextAreaField("Doctor Comment",validators=[InputRequired()])
	image = FileField("Upload Photo",validators=[FileAllowed(images,"Images Only")])

class EditReportForm(FlaskForm):
        title = StringField("Title",validators=[InputRequired(),Length(max=100)])
        report = TextAreaField("Report",validators=[InputRequired()])
        comment = TextAreaField("Doctor Comment",validators=[InputRequired()])
        




class ResetPasswordForm(FlaskForm):
	password = PasswordField("Password",validators=[InputRequired(),EqualTo("confirm",message="Password not Match")])
	confirm = PasswordField("Confirm Password")









###########################################################
########## 								     ##############
##########      ADMIN REGISTRATION & LOGIN   ##############
########## 		ADMIN DASHBOARD	             ##############
########## 									 ##############
###########################################################


@app.route("/register-admin",methods=["GET","POST"])
def RegisterAdmin():
	form = UserRegisterForm()
	if form.validate_on_submit():
		hass_password = generate_password_hash(form.password.data,method="sha256")
		filename = images.save(form.image.data)
		url = "http://mambangsehat.com/static/img/profile/"+filename
		new_admin = User(username=form.username.data,full_name=form.full_name.data,phone=form.phone.data,email=form.email.data,password=hass_password,address=form.address.data,image_name=filename,image_url=url,role="admin")
		
		ex_user = User.query.filter_by(username=form.username.data).all() 
		ex_email = User.query.filter_by(email=form.email.data).all() 

		if len(ex_user) > 0 or len(ex_email) > 0 :
			flash("Username dan Email telah terdaftar,coba yang lain","danger")
			return render_template("admin/register.html",form=form)
		else :
			db.session.add(new_admin)
			db.session.commit()

			flash("Penambahan admin sukses","success")
			return redirect(url_for("LoginAdmin"))
		
	return render_template("admin/register.html",form=form)

@app.route("/login-admin",methods=["GET","POST"])
def LoginAdmin():
	form = UserLoginForm()
	if form.validate_on_submit():
		admin = User.query.filter_by(username=form.username.data).first()
		if admin:
			if check_password_hash(admin.password,form.password.data):
				login_user(admin)
				if admin.role == "admin":
					flash("login sukses","success")
					return redirect(url_for("AdminDashboard"))
				else :
					logout_user()
					flash("Invalid username or password")
					return render_template("admin/login.html",form=form)

		flash("Invalid username or password")
		return render_template("admin/login.html",form=form)

	return render_template("admin/login.html",form=form)	


@app.route("/admin/dashboard",methods=["GET","POST"])
@login_required
@roles_required(role="admin")
def AdminDashboard():
	doctors = User.query.filter_by(role="doctor").all()
	patient = Patient.query.all()
	length_doctor = len(doctors)
	length_patient = len(patient)
	return render_template("admin/dashboard.html",doctors=doctors,length_doctor=length_doctor,length_patient=length_patient)



@app.route("/admin/dashboard/profile",methods=["GET","POST"])
@login_required
@roles_required(role="admin")
def AdminProfile():
	user = User.query.filter_by(id=current_user.id).first()
	form = UserEditForm()
	form.username.data = user.username
	form.full_name.data = user.full_name
	form.phone.data = user.phone
	form.email.data = user.email
	form.address.data = user.address
	if form.validate_on_submit():
		user = User.query.filter_by(id=current_user.id).first()
		user.username = request.form["username"]
		user.full_name = request.form["full_name"]
		user.phone = request.form["phone"]
		user.email = request.form["email"]
		user.address = request.form["address"]

		db.session.commit()
		flash("Profile telah di perbaharui","success")
		return redirect(url_for("AdminDashboard"))
	return render_template("admin/profile.html",user=user,form=form)



@app.route("/admin/dashboard/profile/photo",methods=["GET","POST"])
@login_required
@roles_required(role="admin")
def UpdatePhotoAdmin():
	user = User.query.filter_by(id=current_user.id).first()
	form = UserUploadPhoto()
	if form.validate_on_submit():
		user = User.query.filter_by(id=current_user.id).first()
		filename = images.save(form.image.data)
		url = images.url(filename)
		user.image_name = filename
		user.image_url = url
		db.session.commit()

		flash("Photo Berhasil Di Ganti","success")
		return redirect(url_for("AdminProfile"))
	return render_template("admin/photo.html",user=user,form=form)





@app.route("/admin/dashboard/delete-doctor/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="admin")
def DeleteDoctor(id):
	doctor = User.query.filter_by(id=id).first()
	if doctor.role == "admin" or doctor.role == "user":
		return redirect(url_for("AdminDashboard"))
	else :
		db.session.delete(doctor)
		db.session.commit()
		flash("Doctor berhasil di hapus","success")
		return redirect(url_for("AdminDashboard"))




@app.route("/admin/dashboard/doctor",methods=["GET","POST"])
@login_required
@roles_required(role="admin")
def DoctorList():
	doctors = User.query.filter_by(role="doctor").all()
	return render_template("admin/doctor_list.html",doctors=doctors)





@app.route("/admin/dashboard/doctor/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="admin")
def DoctorProfile(id):
	doctor = User.query.filter_by(id=id).first()
	return render_template("admin/doctor.html",doctor=doctor)



@app.route("/admin/dashboard/patient",methods=["GET","POST"])
@login_required
@roles_required(role="admin")
def AdminSeePatient():
	patients = Patient.query.all()
	return render_template("admin/allpatient.html",patients=patients)


@app.route("/admin/dashboard/patient/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="admin")
def AdminSeePatientProfile(id):
	patient = Patient.query.filter_by(id=id).first()
	reports = Report.query.filter_by(owner_id=id).all()
	return render_template("admin/patient.html",patient=patient,reports=reports)








###########################################################
########## 								     ##############
##########      USER REGISTRATION & LOGIN    ##############
########## 		DOCTOR & USER ROLE 			 ##############
########## 									 ##############
###########################################################


@app.route("/admin/dashboard/register-doctor",methods=["GET","POST"])
@login_required
@roles_required(role="admin")
def RegisterDoctor():
	form = UserRegisterForm()
	if form.validate_on_submit():
		hass_password = generate_password_hash(form.password.data,method="sha256")
		filename = images.save(form.image.data)
		url = images.url(filename)
		new_user = User(username=form.username.data,full_name=form.full_name.data,phone=form.phone.data,email=form.email.data,password=hass_password,address=form.address.data,image_name=filename,image_url=url,role="doctor")

		ex_user = User.query.filter_by(username=form.username.data).all() 
		ex_email = User.query.filter_by(email=form.email.data).all() 

		if len(ex_user) > 0 or len(ex_email) > 0 :
			flash("Username dan Email telah terdaftar,coba yang lain","danger")
			return render_template("doctor/register.html",form=form)

		else :

			db.session.add(new_user)
			db.session.commit()

			flash("Pendaftaran Dokter Berhasil","success")
			return redirect(url_for("AdminDashboard"))
	return render_template("doctor/register.html",form=form)


@app.route("/register-user",methods=["GET","POST"])
def RegisterUser():
	form = UserRegisterForm()
	if form.validate_on_submit():
		hass_password = generate_password_hash(form.password.data,method="sha256")
		filename = images.save(form.image.data)
		url = images.url(filename)
		new_user = User(username=form.username.data,full_name=form.full_name.data,phone=form.phone.data,email=form.email.data,password=hass_password,address=form.address.data,image_name=filename,image_url=url,role="user")

		ex_user = User.query.filter_by(username=form.username.data).all() 
		ex_email = User.query.filter_by(email=form.email.data).all() 

		if len(ex_user) > 0 or len(ex_email) > 0 :

			flash("Username dan Email telah terdaftar,coba yang lain","danger")
			return render_template("user/register.html",form=form)
		else :

			db.session.add(new_user)
			db.session.commit()
			flash("Pendaftaran User Berhasil","success")
			return redirect(url_for("index"))
	return render_template("user/register.html",form=form)


@app.route("/login",methods=["GET","POST"])
def Login():
	form = UserLoginForm()
	if form.validate_on_submit():
		user = User.query.filter_by(username=form.username.data).first()
		if user :
			if check_password_hash(user.password,form.password.data):
				login_user(user)
				if user.role == "user":
					flash("Login sukses","success")
					return redirect(url_for("UserDashboard"))
				elif user.role == "doctor":
					flash("Login sukses","success")
					return redirect(url_for("DoctorDashboard"))
				else :
					logout_user()
					flash("Invalid username or password")
					return render_template("doctor/login.html",form=form)

		flash("Invalid username or password")
		return render_template("doctor/login.html",form=form)

	return render_template("doctor/login.html",form=form)



###########################################################
########## 								     ##############
##########      USER FORGOT PASSWORD      	 ##############
########## 		USER LOGOUT 				 ##############
########## 									 ##############
###########################################################


@app.route("/logout")
@login_required
def Logout():
	logout_user()
	flash("logout sukses","success")
	return redirect(url_for("index"))



@app.route("/reset-password",methods=["GET","POST"])
@login_required
def ResetPasswordUser():
	email = current_user.email 
	token = s.dumps(email, salt="email-confirm")

	msg = Message("Reset Password", sender="makinrame@gmail.com", recipients=[email])

	link = url_for("ResetPassword", token=token, _external=True)

	msg.body = "your link is {}".format(link)
	mail.send(msg)

	logout_user()		
	flash("Anda telah keluar,klik link reset password yang kami kirim di email anda","success")
	return redirect(url_for("index"))



@app.route("/forgot-password",methods=["GET","POST"])
def ForgotPassword():
	if request.method == "POST":
		email = request.form["email"]
		user = User.query.filter_by(email=email).first()
		if user :
			token = s.dumps(email, salt="email-confirm")

			msg = Message("Reset Password", sender="makinrame@gmail.com", recipients=[email])

			link = url_for("ResetPassword", token=token, _external=True)

			msg.body = "your link is {}".format(link)
			mail.send(msg)
		
			flash("Please check your inbox and click reset password link","success")
			return redirect(url_for("Login"))
		else:
			flash("invalid email","danger")
			return "inalid"

	return render_template("doctor/forgot_password.html")

@app.route("/reset-password/<token>",methods=["GET","POST"])
def ResetPassword(token):
	form = ResetPasswordForm()
	try : 
		email = s.loads(token, salt="email-confirm", max_age=3000)
		if form.validate_on_submit():
			user = User.query.filter_by(email=email).first()
			if user :
				hass_password = generate_password_hash(form.password.data,method="sha256")
				user.password = hass_password
				db.session.commit()

				flash("Password Berhasil Di Rubah","success")
				return redirect(url_for("Login"))
	except : 
		flash("Link Expired","danger")
		return redirect(url_for("ForgotPassword"))
	
	return render_template("doctor/reset_password.html",form=form)



###########################################################
########## 								     ##############
##########      DASHBOARD USER 			     ##############
########## 						 			 ##############
########## 									 ##############
###########################################################



@app.route("/user/dashboard")
@login_required
@roles_required(role="user")
def UserDashboard():
	patients = Patient.query.all()
	doctors = User.query.filter_by(role="doctor").all()
	length_doctor = len(doctors)
	length_patient = len(patients)
	return render_template("user/dashboard.html",patients=patients,length_patient=length_patient,length_doctor=length_doctor)



@app.route("/user/dashboard/profile",methods=["GET","POST"])
@login_required
@roles_required(role="user")
def UserProfile():
	user = User.query.filter_by(id=current_user.id).first()
	form = UserEditForm()
	form.username.data = user.username
	form.full_name.data = user.full_name
	form.phone.data = user.phone
	form.email.data = user.email
	form.address.data = user.address
	if form.validate_on_submit():
		new_user = User.query.filter_by(id=current_user.id).first()
		new_user.username = form.username.data
		new_user.full_name = form.full_name.data
		new_user.phone = form.phone.data
		new_user.email = form.email.data
		new_user.address = form.address.data

		db.session.commit()
		flash("Profile telah di perbaharui","success")
		return redirect(url_for("UserDashboard"))

	return render_template("user/profile.html",user=user,form=form)



@app.route("/user/dashboard/profile/photo",methods=["GET","POST"])
@login_required
@roles_required(role="user")
def UpdatePhotoUser():
	user = User.query.filter_by(id=current_user.id).first()
	form = UserUploadPhoto()
	if form.validate_on_submit():
		user = User.query.filter_by(id=current_user.id).first()
		filename = images.save(form.image.data)
		url = images.url(filename)
		user.image_name = filename
		user.image_url = url
		db.session.commit()

		flash("Photo Berhasil Di Ganti","success")
		return redirect(url_for("UserProfile"))
	return render_template("user/photo.html",user=user,form=form)




@app.route("/user/dashboard/doctor",methods=["GET","POST"])
@login_required
@roles_required(role="user")
def UserSeeDoctor():
	doctors  = User.query.filter_by(role="doctor").all()
	return render_template("user/doctorlist.html",doctors=doctors)




@app.route("/user/dashboard/doctor/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="user")
def UserSeeDoctorProfile(id):
	doctor = User.query.filter_by(id=id).first()
	return render_template("user/doctor.html",doctor=doctor)







@app.route("/user/dashboard/patient",methods=["GET","POST"])
@login_required
@roles_required(role="user")
def UserSeePatient():
	patients = Patient.query.all()
	return render_template("user/allpatient.html",patients=patients)




@app.route("/user/dashboard/patient/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="user")
def UserSeePatientProfile(id):
	patient = Patient.query.filter_by(id=id).first()
	reports = Report.query.filter_by(owner_id=id).all()
	return render_template("user/patient.html",patient=patient,reports=reports)









###########################################################
########## 								     ##############
##########      DASHBOARD DOCTOR 			 ##############
########## 						 			 ##############
########## 									 ##############
###########################################################






@app.route("/doctor/dashboard")
@login_required
@roles_required(role="doctor")
def DoctorDashboard():
	patients = Patient.query.all()
	doctors = User.query.filter_by(role="doctor").all()
	length_doctor = len(doctors)
	length_patient = len(patients)
	return render_template("doctor/dashboard.html",patients=patients,length_patient=length_patient,length_doctor=length_doctor)




@app.route("/doctor/dashboard/profile",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def EditDoctorProfile():
	doctor = User.query.filter_by(id=current_user.id).first()
	form = UserEditForm()
	form.username.data = doctor.username
	form.full_name.data = doctor.full_name
	form.phone.data = doctor.phone
	form.email.data = doctor.email
	form.address.data = doctor.address

	if form.validate_on_submit():
		new_doctor = User.query.filter_by(id=current_user.id).first()
		new_doctor.username = request.form["username"]
		new_doctor.full_name = request.form["full_name"]
		new_doctor.phone = request.form["phone"]
		new_doctor.email = request.form["email"]
		new_doctor.address = request.form["address"]

		db.session.commit()
		flash("Profil Berhasil di Update","success")
		return redirect(url_for("DoctorDashboard"))
	return render_template("doctor/profile.html",doctor=doctor,form=form)



@app.route("/doctor/dashboard/profile/photo",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def UpdatePhotoDoctor():
	user = User.query.filter_by(id=current_user.id).first()
	form = UserUploadPhoto()
	if form.validate_on_submit():
		user = User.query.filter_by(id=current_user.id).first()
		filename = images.save(form.image.data)
		url = images.url(filename)
		user.image_name = filename
		user.image_url = url
		db.session.commit()

		flash("Photo Berhasil Di Ganti","success")
		return redirect(url_for("EditDoctorProfile"))
	return render_template("user/photo.html",user=user,form=form)




@app.route("/doctor/dashboard/doctor",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def ViewDoctorList():
	doctors = User.query.filter_by(role="doctor").all()
	return render_template("doctor/doctorlist.html",doctors=doctors)



@app.route("/doctor/dashboard/doctor/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def ViewDoctorProfile(id):
	doctor = User.query.filter_by(id=id).first()
	return render_template("doctor/doctorprofile.html",doctor=doctor)







@app.route("/doctor/dashboard/patient",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def DoctorSeePatient():
	patients = Patient.query.all()
	return render_template("doctor/allpatient.html",patients=patients)




@app.route("/doctor/dashboard/patient/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def DoctorSeePatientProfile(id):
	patient = Patient.query.filter_by(id=id).first()
	reports = Report.query.filter_by(owner_id=id).all()
	
	return render_template("doctor/patient.html",patient=patient,reports=reports)





@app.route("/doctor/dashboard/add-patient",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def AddPatient():
	form = AddPatientForm()
	if form.validate_on_submit():
		filename = images.save(form.image.data)
		url = images.url(filename)
		patient = Patient(name=form.name.data,phone=form.phone.data,birthdate=form.birthdate.data,address=form.address.data,description=form.description.data,image_name=filename,image_url=url)
		db.session.add(patient)
		db.session.commit()

		flash("Pasien Berhasil Di Tambahkan","success")
		return redirect(url_for("DoctorDashboard"))
	return render_template("doctor/add_patient.html",form=form)





@app.route("/doctor/dashboard/edit-patient/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def EditPatient(id):
	patient = Patient.query.filter_by(id=id).first()
	form = AddPatientForm()
	form.name.data = patient.name
	form.phone.data = patient.phone
	form.birthdate.data = patient.birthdate
	form.address.data = patient.address
	form.description.data = patient.description

	if form.validate_on_submit():
		patient = Patient.query.filter_by(id=id).first()
		patient.name = request.form["name"]
		patient.phone = request.form["phone"]
		patient.birthdate = request.form["birthdate"]
		patient.address = request.form["address"]
		patient.description = request.form["description"]

		db.session.commit()
		flash("Pasien sukses di update","success")
		return redirect(url_for("DoctorDashboard"))
	return render_template("doctor/edit_patient.html",form=form,patient=patient)




@app.route("/doctor/dashboard/delete-patient/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def DeletePatient(id):
	patient = Patient.query.filter_by(id=id).first()
	db.session.delete(patient)
	db.session.commit()
	flash("Pasien sukses di hapus","success")
	return redirect(url_for("DoctorDashboard"))


@app.route("/doctor/dashboard/patient/photo/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def EditPatientPhoto(id):
	patient = Patient.query.filter_by(id=id).first()
	form = UserUploadPhoto()
	if form.validate_on_submit():
		filename = images.save(form.image.data)
		url = images.url(filename)
		patient.image_name = filename
		patient.image_url = url
		db.session.commit()

		flash("Photo berhasil di ganti","success")
		return redirect(url_for("DoctorSeePatientProfile",id=id))
	return render_template("doctor/editpatientphoto.html",form=form)



@app.route("/doctor/dashboard/add-report/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def PatientReport(id):
	form = ReportForm()
	if form.validate_on_submit():
		filename = images.save(form.image.data)
		url = images.url(filename)
		report = Report(title=form.title.data,report=form.report.data,doctor=current_user.username,owner_id=id,comment=form.comment.data,image_name=filename,image_url=url)
		db.session.add(report)
		db.session.commit()
		flash("Report berhasil di tambahkan","success")
		return redirect(url_for("DoctorDashboard"))
	return render_template("doctor/add_report.html",form=form)



@app.route("/doctor/dashboard/edit-report/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def EditPatientReport(id):
	report = Report.query.filter_by(id=id).first()
	form = EditReportForm()
	form.title.data = report.title
	form.report.data = report.report
	form.comment.data = report.comment
	if form.validate_on_submit():
		new_report = Report.query.filter_by(id=id).first()
		new_report.title = request.form["title"]
		new_report.report = request.form["report"]
		new_report.comment = request.form["comment"]
		db.session.commit()

		flash("Report berhasil di rubah","success")
		return redirect(url_for("DoctorSeePatient"))
	return render_template("doctor/edit_report.html",form=form)

@app.route("/doctor/dashboard/delete-report/<string:id>",methods=["GET","POST"])
@login_required
@roles_required(role="doctor")
def DeleteReport(id):
	report = Report.query.filter_by(id=id).first()
	db.session.delete(report)
	db.session.commit()

	flash("Report berhasil di hapus","success")
	return redirect(url_for("DoctorSeePatient"))




@app.route("/")
def index():
	return render_template("index.html")


# if __name__ == "__main__":
# 	#manager.run()
# 	app.run(debug=True)
