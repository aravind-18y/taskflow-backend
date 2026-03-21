import os
import datetime
import jwt
from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_cors import CORS
from functools import wraps

app = Flask(__name__)

# --- CONFIGURATION ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'taskflow_final_2026')

db_url = os.environ.get('DATABASE_URL', 'sqlite:///tasks.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --- CORS FIX ---
# Using flask_cors for all routes, AND a manual after_request handler
# as a safety net. This dual approach fixes all Render + Vercel CORS issues.
CORS(app,
     resources={r"/*": {"origins": "*"}},
     allow_headers=["Content-Type", "x-access-token"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     supports_credentials=False)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


# --- MANUAL CORS SAFETY NET ---
# This fires on EVERY response and injects the headers directly.
# It catches any case where flask_cors misses a route.
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, x-access-token"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


# --- GLOBAL OPTIONS HANDLER ---
# Handles ALL preflight requests in one place so no route can miss it.
@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    return make_response('', 204)


# --- MODELS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    tasks = db.relationship('Task', backref='owner',
                            lazy=True, cascade="all, delete-orphan")


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default="Pending")
    priority = db.Column(db.String(20), default="Medium")
    category = db.Column(db.String(50), default="Personal")
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
            current_user = db.session.get(User, data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired, please login again'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token invalid'}), 401
        return f(current_user, *args, **kwargs)
    return decorated


# --- ROUTES ---

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password required'}), 400
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists'}), 400
    hashed = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Username and password required'}), 400
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
        return jsonify([{
            'id': t.id, 'title': t.title,
            'status': t.status, 'priority': t.priority, 'category': t.category
        } for t in tasks])
    data = request.get_json()
    if not data or not data.get('title'):
        return jsonify({'message': 'Title is required'}), 400
    new_task = Task(
        title=data['title'],
        user_id=current_user.id,
        priority=data.get('priority', 'Medium'),
        category=data.get('category', 'Personal')
    )
    db.session.add(new_task)
    db.session.commit()
    return jsonify({
        'id': new_task.id, 'title': new_task.title,
        'status': new_task.status, 'priority': new_task.priority, 'category': new_task.category
    }), 201


@app.route('/tasks/<int:id>/toggle', methods=['PUT'])
@token_required
def toggle_task(current_user, id):
    task = Task.query.filter_by(id=id, user_id=current_user.id).first()
    if not task:
        return jsonify({'message': 'Not found'}), 404
    task.status = "Completed" if task.status == "Pending" else "Pending"
    db.session.commit()
    return jsonify({'id': task.id, 'status': task.status}), 200


@app.route('/tasks/<int:id>', methods=['DELETE'])
@token_required
def delete_task(current_user, id):
    task = Task.query.filter_by(id=id, user_id=current_user.id).first()
    if not task:
        return jsonify({'message': 'Not found'}), 404
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Deleted'}), 200


# Health check — also wakes up the Render instance
@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'}), 200


if __name__ == '__main__':
    app.run(debug=True)
