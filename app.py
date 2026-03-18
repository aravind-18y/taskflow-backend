import os
import datetime
import jwt
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'taskflow_final_2026')

# DATABASE: Automatically switches between Render Postgres and Local SQLite
db_url = os.environ.get('DATABASE_URL', 'sqlite:///tasks.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- THE PERFECT CORS FIX ---
# This allows your Vercel frontend to talk to Render without errors
CORS(app, resources={r"/*": {
    "origins": "*",
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    "allow_headers": ["Content-Type", "x-access-token"]
}})

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- MODELS ---


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="Pending")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


with app.app_context():
    db.create_all()

# --- AUTH DECORATOR ---


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token missing'}), 401
        try:
            data = jwt.decode(
                token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# --- ROUTES ---


@app.route('/register', methods=['POST', 'OPTIONS'])
def register():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    data = request.get_json()
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = bcrypt.generate_password_hash(
        data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'}), 201


@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token, 'username': user.username}), 200
    return jsonify({'message': 'Invalid credentials'}), 401


@app.route('/tasks', methods=['GET', 'POST'])
@token_required
def handle_tasks(current_user):
    if request.method == 'GET':
        tasks = Task.query.filter_by(user_id=current_user.id).all()
        return jsonify([{'id': t.id, 'title': t.title, 'status': t.status} for t in tasks])
    data = request.get_json()
    new_task = Task(title=data['title'], user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'id': new_task.id, 'title': new_task.title, 'status': new_task.status}), 201


@app.route('/tasks/<int:id>', methods=['DELETE'])
@token_required
def delete_task(current_user, id):
    task = Task.query.filter_by(id=id, user_id=current_user.id).first()
    if not task:
        return jsonify({'message': 'Not found'}), 404
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Deleted'}), 200


if __name__ == '__main__':
    app.run(debug=True)
