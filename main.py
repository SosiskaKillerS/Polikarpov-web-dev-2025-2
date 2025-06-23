from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime, date
import os
from dotenv import load_dotenv
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError

# Загружаем переменные окружения
load_dotenv()

app = Flask(__name__)

# Конфигурация PostgreSQL
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:1231@localhost:5432/volunteer'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')

# Инициализация расширений
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите, чтобы получить доступ к этой странице.'
login_manager.login_message_category = 'info'
CORS(app)

# Определение моделей БД
class Role(db.Model):
    __tablename__ = 'roles'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
    
    # Связь с пользователями
    users = db.relationship('User', backref='role', lazy=True)

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    last_name = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    middle_name = db.Column(db.String(100), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'), nullable=False)
    
    # Связи
    organized_events = db.relationship('Event', backref='organizer', lazy=True)
    registrations = db.relationship('VolunteerRegistration', backref='user', lazy=True)

class Event(db.Model):
    __tablename__ = 'events'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_date = db.Column(db.Date, nullable=False)
    location = db.Column(db.String(255), nullable=False)
    required_volunteers = db.Column(db.Integer, nullable=False)
    image_filename = db.Column(db.String(255), nullable=False)
    organizer_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Связи
    registrations = db.relationship('VolunteerRegistration', backref='event', lazy=True, cascade="all, delete-orphan")

class VolunteerRegistration(db.Model):
    __tablename__ = 'volunteer_registrations'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('events.id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    contact_info = db.Column(db.String(255), nullable=False)
    registration_date = db.Column(db.DateTime(timezone=True), server_default=db.func.now(), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)

    __table_args__ = (
        db.UniqueConstraint('event_id', 'user_id', name='_event_user_uc'),
        db.CheckConstraint(status.in_(['pending', 'accepted', 'rejected']), name='check_status_values')
    )

# --- Формы ---
class RegistrationForm(FlaskForm):
    login = StringField('Логин', 
                        validators=[DataRequired(), Length(min=4, max=50)])
    first_name = StringField('Имя', 
                             validators=[DataRequired(), Length(min=2, max=100)])
    last_name = StringField('Фамилия', 
                            validators=[DataRequired(), Length(min=2, max=100)])
    middle_name = StringField('Отчество (необязательно)', 
                              validators=[Length(max=100)])
    password = PasswordField('Пароль', 
                             validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Подтвердите пароль', 
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

    def validate_login(self, login):
        user = User.query.filter_by(login=login.data).first()
        if user:
            raise ValidationError('Этот логин уже занят. Пожалуйста, выберите другой.')

class LoginForm(FlaskForm):
    login = StringField('Логин', 
                        validators=[DataRequired(), Length(min=4, max=50)])
    password = PasswordField('Пароль', 
                             validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')

# Функция для загрузки пользователя
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Функция для создания ролей по умолчанию
def create_default_roles():
    roles = [
        {'name': 'admin', 'description': 'Администратор (суперпользователь, полный доступ к системе)'},
        {'name': 'moderator', 'description': 'Модератор (редактирование мероприятий и модерация регистраций)'},
        {'name': 'user', 'description': 'Пользователь (просмотр информации и регистрация на мероприятия)'}
    ]
    
    for role_data in roles:
        existing_role = Role.query.filter_by(name=role_data['name']).first()
        if not existing_role:
            role = Role(**role_data)
            db.session.add(role)
    
    db.session.commit()

# Базовый маршрут
@app.route('/')
def index():
    return render_template('index.html')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        # Назначаем роль 'user' по умолчанию
        user_role = Role.query.filter_by(name='user').first()
        if not user_role:
            # Если роль не найдена, можно создать ее или вызвать ошибку
            flash('Ошибка: роль "user" не найдена. Обратитесь к администратору.', 'danger')
            return redirect(url_for('register'))

        user = User(
            login=form.login.data, 
            password_hash=hashed_password,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            middle_name=form.middle_name.data,
            role=user_role
        )
        db.session.add(user)
        db.session.commit()
        flash(f'Аккаунт для {form.login.data} был успешно создан! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Регистрация', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(login=form.login.data).first()
        if user and bcrypt.check_password_hash(user.password_hash, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Неверный логин или пароль. Пожалуйста, попробуйте снова.', 'danger')
    return render_template('login.html', title='Авторизация', form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('index'))

# Маршрут для тестирования подключения к БД
@app.route('/test_db')
def test_db():
    try:
        # Проверяем подключение к БД, используя text()
        db.session.execute(text('SELECT 1'))
        return jsonify({'status': 'success', 'message': 'База данных подключена успешно!'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Ошибка подключения к БД: {str(e)}'})

if __name__ == '__main__':
    with app.app_context():
        # Создаем все таблицы
        db.create_all()
        # Создаем роли по умолчанию
        create_default_roles()
        print("База данных инициализирована успешно!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
