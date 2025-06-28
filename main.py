from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
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
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, DateField, FileField, IntegerField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Optional
import bleach
import markdown
from flask import abort
import math
from werkzeug.utils import secure_filename

# Загружаем переменные окружения
load_dotenv()

app = Flask(__name__)

# Конфигурация PostgreSQL
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')

# Инициализация расширений
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
login_manager = LoginManager(app)
csrf = CSRFProtect(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Пожалуйста, войдите, чтобы получить доступ к этой странице.'
login_manager.login_message_category = 'info'
CORS(app)

# --- Декоратор для проверки ролей ---
def role_required(*roles):
    def decorator(f):
        from functools import wraps
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Для выполнения данного действия необходимо пройти процедуру аутентификации.', 'warning')
                return redirect(url_for('login', next=request.url))
            if current_user.role.name not in roles:
                flash('У вас недостаточно прав для выполнения данного действия.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Модели (с учетом каскадных удалений и правильных связей) ---
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text, nullable=False)
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
    organized_events = db.relationship('Event', backref='organizer', lazy=True)
    registrations = db.relationship('VolunteerRegistration', backref='user', lazy=True, cascade="all, delete-orphan")

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

class EventForm(FlaskForm):
    title = StringField('Название мероприятия', 
                        validators=[DataRequired(), Length(min=3, max=255)])
    description = TextAreaField('Описание мероприятия', 
                                validators=[DataRequired(), Length(min=10)], 
                                render_kw={'required': False, 'minlength': None})
    event_date = DateField('Дата мероприятия', 
                             validators=[DataRequired()])
    location = StringField('Место проведения', 
                           validators=[DataRequired(), Length(min=3, max=255)])
    required_volunteers = IntegerField('Требуемое количество волонтёров', 
                                      validators=[DataRequired()])
    image = FileField('Изображение (необязательно)', validators=[Optional()])
    submit = SubmitField('Сохранить')

    def validate_required_volunteers(self, required_volunteers):
        if required_volunteers.data <= 0:
            raise ValidationError('Количество волонтёров должно быть положительным числом')

    def validate_image(self, image):
        if image.data and image.data.filename:
            # Проверяем расширение файла
            allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg'}
            file_extension = image.data.filename.rsplit('.', 1)[1].lower() if '.' in image.data.filename else ''
            if file_extension not in allowed_extensions:
                raise ValidationError('Разрешены только файлы изображений: PNG, JPG, JPEG, GIF, WEBP, SVG')
            
            # Проверяем размер файла (максимум 5MB)
            if len(image.data.read()) > 5 * 1024 * 1024:
                image.data.seek(0)  # Сбрасываем указатель файла
                raise ValidationError('Размер файла не должен превышать 5MB')
            image.data.seek(0)  # Сбрасываем указатель файла

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

# --- Главная страница с фильтрацией, пагинацией, метками, кнопками по ролям ---
@app.route('/')
def index():
    page = request.args.get('page', 1, type=int)
    today = datetime.utcnow().date()
    events_query = Event.query.filter(Event.event_date >= today).order_by(Event.event_date.desc())
    total_events = events_query.count()
    per_page = 10
    events = events_query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('index.html', events=events.items, pagination=events, total_events=total_events)

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
        if user:
            # Проверяем сначала как хешированный пароль
            try:
                if bcrypt.check_password_hash(user.password_hash, form.password.data):
                    login_user(user, remember=form.remember.data)
                    next_page = request.args.get('next')
                    return redirect(next_page) if next_page else redirect(url_for('index'))
            except ValueError:
                # Если хеш поврежден, проверяем как обычный пароль
                pass
            
            # Проверяем как обычный пароль (для admin, moderator и других пользователей с нехешированными паролями)
            if user.password_hash == form.password.data:
                login_user(user, remember=form.remember.data)
                next_page = request.args.get('next')
                return redirect(next_page) if next_page else redirect(url_for('index'))
            
            flash('Неверный логин или пароль. Пожалуйста, попробуйте снова.', 'danger')
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

# --- Добавление мероприятия (форма и обработка) ---
@app.route('/event/add', methods=['GET', 'POST'])
@role_required('admin')
def add_event():
    form = EventForm()
    if request.method == 'POST':
        print(f"Форма валидна: {form.validate()}")
        if form.errors:
            print(f"Ошибки формы: {form.errors}")
        print(f"Данные формы: title={form.title.data}, date={form.event_date.data}, location={form.location.data}, volunteers={form.required_volunteers.data}")
    
    if form.validate_on_submit():
        try:
            # Обрабатываем изображение
            image_filename = 'default'
            if form.image.data and form.image.data.filename:
                # Сохраняем файл
                filename = secure_filename(form.image.data.filename)
                # Создаем уникальное имя файла
                name, ext = os.path.splitext(filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                image_filename = f"{name}_{timestamp}{ext}"
                
                # Сохраняем файл в папку static/images
                upload_folder = os.path.join(app.root_path, 'static', 'images')
                os.makedirs(upload_folder, exist_ok=True)
                file_path = os.path.join(upload_folder, image_filename)
                form.image.data.save(file_path)
            
            # Создаем мероприятие
            event = Event(
                title=form.title.data,
                description=form.description.data,
                event_date=form.event_date.data,
                location=form.location.data,
                required_volunteers=form.required_volunteers.data,
                image_filename=image_filename,
                organizer_id=current_user.id
            )
            
            db.session.add(event)
            db.session.commit()
            
            flash(f'Мероприятие "{event.title}" успешно создано!', 'success')
            return redirect(url_for('view_event', event_id=event.id))
            
        except Exception as e:
            db.session.rollback()
            print(f"Ошибка при создании мероприятия: {str(e)}")
            print(f"Тип ошибки: {type(e).__name__}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            flash(f'При сохранении данных возникла ошибка: {str(e)}. Проверьте корректность введённых данных.', 'danger')
    
    return render_template('event_form.html', form=form, title='Добавить мероприятие', is_edit=False)

# --- Редактирование мероприятия ---
@app.route('/event/<int:event_id>/edit', methods=['GET', 'POST'])
@role_required('admin', 'moderator')
def edit_event(event_id):
    event = Event.query.get_or_404(event_id)
    form = EventForm()
    
    if request.method == 'GET':
        form.title.data = event.title
        form.description.data = event.description
        form.event_date.data = event.event_date
        form.location.data = event.location
        form.required_volunteers.data = event.required_volunteers
    
    if form.validate_on_submit():
        try:
            # Обрабатываем новое изображение, если загружено
            if form.image.data and form.image.data.filename:
                # Сохраняем новый файл
                filename = secure_filename(form.image.data.filename)
                name, ext = os.path.splitext(filename)
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                image_filename = f"{name}_{timestamp}{ext}"
                
                # Сохраняем файл в папку static/images
                upload_folder = os.path.join(app.root_path, 'static', 'images')
                os.makedirs(upload_folder, exist_ok=True)
                file_path = os.path.join(upload_folder, image_filename)
                form.image.data.save(file_path)
                
                # Обновляем имя файла в базе
                event.image_filename = image_filename
            
            # Обновляем данные мероприятия
            event.title = form.title.data
            event.description = form.description.data
            event.event_date = form.event_date.data
            event.location = form.location.data
            event.required_volunteers = form.required_volunteers.data
            
            db.session.commit()
            
            flash(f'Мероприятие "{event.title}" успешно обновлено!', 'success')
            return redirect(url_for('view_event', event_id=event.id))
            
        except Exception as e:
            db.session.rollback()
            flash('При сохранении данных возникла ошибка. Проверьте корректность введённых данных.', 'danger')
    
    return render_template('event_form.html', form=form, title='Редактировать мероприятие', is_edit=True, event=event)

# --- Удаление мероприятия ---
@app.route('/event/<int:event_id>/delete', methods=['POST'])
@role_required('admin')
def delete_event(event_id):
    event = Event.query.get_or_404(event_id)
    try:
        db.session.delete(event)
        db.session.commit()
        flash(f'Мероприятие "{event.title}" успешно удалено.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при удалении мероприятия.', 'danger')
    return redirect(url_for('index'))

# --- Просмотр мероприятия ---
@app.route('/event/<int:event_id>', methods=['GET', 'POST'])
def view_event(event_id):
    event = Event.query.get_or_404(event_id)
    reg_count = len([r for r in event.registrations if r.status == 'accepted'])
    required = event.required_volunteers or 0
    is_closed = reg_count >= required
    # Markdown + bleach для описания
    allowed_tags = [
        'a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'strong', 'ul', 'p', 'br', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
    ]
    description_html = bleach.clean(markdown.markdown(event.description), tags=allowed_tags, strip=True)
    # Список волонтёров (accepted)
    accepted_regs = [r for r in event.registrations if r.status == 'accepted']
    # Список заявок (pending)
    pending_regs = [r for r in event.registrations if r.status == 'pending']
    # Для текущего пользователя — его заявка (если есть)
    user_reg = None
    if current_user.is_authenticated:
        user_reg = VolunteerRegistration.query.filter_by(event_id=event.id, user_id=current_user.id).first()
    # Для обработки принятия/отклонения заявки (POST)
    if request.method == 'POST' and current_user.is_authenticated and (
        current_user.role.name in ['admin', 'moderator'] or 
        current_user.id == event.organizer_id
    ):
        reg_id = request.form.get('reg_id')
        action = request.form.get('action')
        reg = VolunteerRegistration.query.get(reg_id)
        if reg and reg.status == 'pending' and reg.event_id == event.id:
            try:
                if action == 'accept':
                    reg.status = 'accepted'
                    db.session.commit()
                    # Если набрано нужное число волонтёров — остальные pending отклонить
                    accepted_now = VolunteerRegistration.query.filter_by(event_id=event.id, status='accepted').count()
                    if accepted_now >= required:
                        left = VolunteerRegistration.query.filter_by(event_id=event.id, status='pending').all()
                        for r in left:
                            r.status = 'rejected'
                        db.session.commit()
                    flash('Заявка принята.', 'success')
                elif action == 'reject':
                    reg.status = 'rejected'
                    db.session.commit()
                    flash('Заявка отклонена.', 'info')
            except Exception as e:
                db.session.rollback()
                flash('Ошибка при обработке заявки.', 'danger')
        return redirect(url_for('view_event', event_id=event.id))
    return render_template('event_view.html', event=event, reg_count=reg_count, required=required, is_closed=is_closed, description_html=description_html, accepted_regs=accepted_regs, pending_regs=pending_regs, user_reg=user_reg)

# --- Служебный маршрут для изображений (если понадобится) ---
@app.route('/images/<filename>')
def event_image(filename):
    return send_from_directory('static/images', filename)

@app.route('/profile')
@login_required
def profile():
    # Получаем мероприятия, которые создал пользователь
    user_events = Event.query.filter_by(organizer_id=current_user.id).order_by(Event.event_date.desc()).all()
    
    # Получаем заявки пользователя на мероприятия
    user_registrations = VolunteerRegistration.query.filter_by(user_id=current_user.id).order_by(VolunteerRegistration.registration_date.desc()).all()
    
    return render_template('profile.html', user_events=user_events, user_registrations=user_registrations)

@app.template_filter('find_image')
def find_image(image_filename):
    static_folder = os.path.join(app.root_path, 'static', 'images')
    
    # Если имя файла уже содержит расширение
    if '.' in image_filename:
        file_path = os.path.join(static_folder, image_filename)
        if os.path.isfile(file_path):
            return 'images/' + image_filename
    
    # Если имя файла без расширения, ищем по расширениям
    for ext in ['.jpg', '.jpeg', '.png', '.webp', '.gif', '.svg']:
        candidate = image_filename + ext
        if os.path.isfile(os.path.join(static_folder, candidate)):
            return 'images/' + candidate
    
    return 'images/no-image.svg'

@app.route('/event/<int:event_id>/register', methods=['POST'])
@login_required
def register_for_event(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Проверяем, не является ли пользователь организатором мероприятия
    if current_user.id == event.organizer_id:
        flash('Организатор не может зарегистрироваться на своё мероприятие.', 'warning')
        return redirect(url_for('view_event', event_id=event_id))
    
    if VolunteerRegistration.query.filter_by(event_id=event_id, user_id=current_user.id).first():
        flash('Вы уже подали заявку на это мероприятие.', 'info')
        return redirect(url_for('view_event', event_id=event_id))
    contact_info = request.form.get('contact_info')
    if not contact_info:
        flash('Пожалуйста, укажите контактную информацию.', 'warning')
        return redirect(url_for('view_event', event_id=event_id))
    try:
        reg = VolunteerRegistration(
            event_id=event_id,
            user_id=current_user.id,
            contact_info=contact_info,
            status='pending'
        )
        db.session.add(reg)
        db.session.commit()
        flash('Заявка успешно отправлена!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Ошибка при отправке заявки.', 'danger')
    return redirect(url_for('view_event', event_id=event_id))

if __name__ == '__main__':
    with app.app_context():
        # Создаем все таблицы
        db.create_all()
        # Создаем роли по умолчанию
        create_default_roles()
        print("База данных инициализирована успешно!")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
