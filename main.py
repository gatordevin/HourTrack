import os
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, redirect, url_for, request,
                   flash, jsonify)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, login_user, logout_user,
                         current_user, login_required, UserMixin)
from flask_socketio import SocketIO, emit, join_room

from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app and configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///time_tracker.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app, async_mode='eventlet')

##############################
#       Database Models      #
##############################

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

    activities = db.relationship('Activity', backref='user', lazy=True)
    timer_session = db.relationship('TimerSession', backref='user', uselist=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Activity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    description = db.Column(db.String(256), nullable=False)
    total_seconds = db.Column(db.Integer, nullable=False)

class TimerSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    start_time = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    last_started = db.Column(db.DateTime, nullable=True)  # when timer last resumed
    accumulated_seconds = db.Column(db.Integer, default=0)  # total seconds so far
    is_running = db.Column(db.Boolean, default=True)  # True if counting

    def get_elapsed(self):
        """Return the total elapsed seconds including the current run."""
        elapsed = self.accumulated_seconds
        if self.is_running and self.last_started:
            elapsed += int((datetime.utcnow() - self.last_started).total_seconds())
        return elapsed

##############################
#       Login Manager        #
##############################

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("Admin access required.", "danger")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

##############################
#          Routes            #
##############################

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# --------- Login & Registration ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash("Logged in successfully.", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Simple registration page (in production, add more checks)
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check for existing user
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "danger")
            return redirect(url_for('register'))
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.", "info")
    return redirect(url_for('login'))

# --------- Dashboard & Timer ----------
@app.route('/dashboard')
@login_required
def dashboard():
    # Get past tasks for the current user
    activities = Activity.query.filter_by(user_id=current_user.id).order_by(Activity.start_time.desc()).all()
    # Check if there's an active timer session
    timer_session = TimerSession.query.filter_by(user_id=current_user.id).first()
    return render_template('dashboard.html', activities=activities, timer_session=timer_session)

@app.route('/start_timer', methods=['POST'])
@login_required
def start_timer():
    # If no timer exists for user, create one. Otherwise, ignore.
    timer = TimerSession.query.filter_by(user_id=current_user.id).first()
    if timer is None:
        now = datetime.utcnow()
        timer = TimerSession(user_id=current_user.id,
                             start_time=now,
                             last_started=now,
                             accumulated_seconds=0,
                             is_running=True)
        db.session.add(timer)
        db.session.commit()
        broadcast_timer_update(current_user.id)
        return jsonify({'status': 'started'})
    else:
        return jsonify({'status': 'already running'}), 400

@app.route('/pause_timer', methods=['POST'])
@login_required
def pause_timer():
    timer = TimerSession.query.filter_by(user_id=current_user.id).first()
    if timer and timer.is_running:
        now = datetime.utcnow()
        # Add the time elapsed since last resumed
        timer.accumulated_seconds += int((now - timer.last_started).total_seconds())
        timer.is_running = False
        timer.last_started = None
        db.session.commit()
        broadcast_timer_update(current_user.id)
        return jsonify({'status': 'paused'})
    return jsonify({'status': 'no running timer'}), 400

@app.route('/resume_timer', methods=['POST'])
@login_required
def resume_timer():
    timer = TimerSession.query.filter_by(user_id=current_user.id).first()
    if timer and not timer.is_running:
        timer.last_started = datetime.utcnow()
        timer.is_running = True
        db.session.commit()
        broadcast_timer_update(current_user.id)
        return jsonify({'status': 'resumed'})
    return jsonify({'status': 'timer already running or not found'}), 400

@app.route('/stop_timer', methods=['POST'])
@login_required
def stop_timer():
    """Stop the timer, require a description, save as an Activity and remove TimerSession."""
    description = request.form.get('description', '').strip()
    if not description:
        return jsonify({'status': 'error', 'message': 'Description required.'}), 400

    timer = TimerSession.query.filter_by(user_id=current_user.id).first()
    if not timer:
        return jsonify({'status': 'error', 'message': 'No active timer.'}), 400

    now = datetime.utcnow()
    # If running, add elapsed time
    if timer.is_running and timer.last_started:
        timer.accumulated_seconds += int((now - timer.last_started).total_seconds())

    elapsed = timer.accumulated_seconds
    # Create an Activity record
    activity = Activity(user_id=current_user.id,
                        start_time=timer.start_time,
                        end_time=now,
                        description=description,
                        total_seconds=elapsed)
    db.session.add(activity)
    # Remove the timer session
    db.session.delete(timer)
    db.session.commit()
    broadcast_timer_update(current_user.id)  # so other devices know it stopped
    return jsonify({'status': 'stopped', 'elapsed': elapsed})

@app.route('/get_timer_state')
@login_required
def get_timer_state():
    timer = TimerSession.query.filter_by(user_id=current_user.id).first()
    if timer:
        data = {
            'accumulated': timer.get_elapsed(),
            'is_running': timer.is_running,
            'start_time': timer.start_time.isoformat()
        }
    else:
        data = None
    return jsonify(data)

# --------- Admin Page ----------
@app.route('/admin', methods=['GET', 'POST'])
@login_required
@admin_required
def admin():
    # Admin can optionally set a date range
    start_date_str = request.args.get('start_date', '')
    end_date_str = request.args.get('end_date', '')
    tz_offset = request.args.get('tz_offset', None)
    query = Activity.query
    filter_desc = ""
    if start_date_str and end_date_str:
        try:
            # Parse the local dates (as entered by the user)
            local_start_date = datetime.strptime(start_date_str, '%Y-%m-%d')
            local_end_date = datetime.strptime(end_date_str, '%Y-%m-%d') + timedelta(days=1)
            # getTimezoneOffset returns the offset in minutes (e.g. 300 for EST)
            try:
                tz_offset = int(tz_offset) if tz_offset is not None else 0
            except ValueError:
                tz_offset = 0
            # Convert local dates to UTC by adding the offset
            utc_start_date = local_start_date + timedelta(minutes=tz_offset)
            utc_end_date = local_end_date + timedelta(minutes=tz_offset)
            query = query.filter(Activity.start_time >= utc_start_date,
                                 Activity.start_time < utc_end_date)
            filter_desc = f"from {start_date_str} to {end_date_str}"
        except Exception as e:
            flash("Invalid date format. Use YYYY-MM-DD.", "danger")
    activities = query.order_by(Activity.start_time.desc()).all()
    
    # Compute total hours per user
    totals = {}
    for act in activities:
        totals.setdefault(act.user.username, 0)
        totals[act.user.username] += act.total_seconds

    # Convert seconds to hours with two decimals
    for user in totals:
        totals[user] = round(totals[user] / 3600, 2)
        
    return render_template('admin.html', activities=activities, totals=totals, filter_desc=filter_desc)

##############################
#      SocketIO Events       #
##############################

@socketio.on('join')
def on_join(data):
    """Join a room based on user_id for receiving timer updates."""
    user_id = data.get('user_id')
    if user_id:
        join_room(str(user_id))

def broadcast_timer_update(user_id):
    """Send the current timer state to all sockets in the user room."""
    timer = TimerSession.query.filter_by(user_id=user_id).first()
    if timer:
        data = {
            'accumulated': timer.get_elapsed(),
            'is_running': timer.is_running,
            'start_time': timer.start_time.isoformat()
        }
    else:
        data = None
    socketio.emit('timer_update', data, room=str(user_id))

##############################
#       Command Line         #
##############################

if __name__ == '__main__':
    # Create DB tables if they don't exist
    with app.app_context():
        db.create_all()
        # Create a default admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('adminpass')
            db.session.add(admin_user)
            db.session.commit()
    socketio.run(app, debug=True, port=8080)
