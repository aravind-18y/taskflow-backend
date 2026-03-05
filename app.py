from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import jwt
import datetime
import os
from functools import wraps

app = Flask(__name__)
CORS(app)
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'taskflow_final_secure_2026'

# Database Setup
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + \
    os.path.join(basedir, 'tasks.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    tasks = db.relationship('Task', backref='owner', lazy=True)


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default="In Progress")
    due_date = db.Column(db.String(50), nullable=True)
    priority = db.Column(db.String(10), default="Medium")
    category = db.Column(db.String(20), default="Personal")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


with app.app_context():
    db.create_all()

# Auth Decorator


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


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists'}), 400
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Registered successfully'}), 201


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    # Corrected check_password_hash
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = jwt.encode({'user_id': user.id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(hours=24)}, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({'token': token, 'username': user.username})
    return jsonify({'message': 'Login failed'}), 401


@app.route("/analytics", methods=["GET"])
@token_required
def get_analytics(current_user):
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    total = len(tasks)
    cat_counts = {}
    for t in tasks:
        cat_counts[t.category] = cat_counts.get(t.category, 0) + 1
    completed = len([t for t in tasks if t.status == "Completed"])
    rate = round((completed / total * 100), 1) if total > 0 else 0
    return jsonify({
        "rate": rate,
        "completionData": [{"name": "Done", "value": completed, "fill": "#10b981"}, {"name": "Pending", "value": total-completed, "fill": "#6366f1"}],
        "categoryData": [{"name": k, "value": v} for k, v in cat_counts.items()],
        "metrics": [{"label": "Productivity Score", "value": f"{rate}%"}, {"label": "Active Tasks", "value": total-completed}, {"label": "Goals Met", "value": completed}]
    })


@app.route("/tasks", methods=["GET", "POST"])
@token_required
def manage_tasks(current_user):
    if request.method == "GET":
        tasks = Task.query.filter_by(user_id=current_user.id).all()
        return jsonify([{"id": t.id, "title": t.title, "status": t.status, "due_date": t.due_date, "priority": t.priority, "category": t.category} for t in tasks])
    data = request.json
    new_task = Task(title=data.get('title'), due_date=data.get('due_date'), priority=data.get(
        'priority', 'Medium'), category=data.get('category', 'Personal'), user_id=current_user.id)
    db.session.add(new_task)
    db.session.commit()
    return jsonify({"id": new_task.id, "title": new_task.title}), 201


@app.route("/tasks/<int:task_id>/toggle", methods=["PUT"])
@token_required
def toggle(current_user, task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
    task.status = "Completed" if task.status == "In Progress" else "In Progress"
    db.session.commit()
    return jsonify({"status": task.status})


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
@token_required
def delete(current_user, task_id):
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first()
    if task:
        db.session.delete(task)
        db.session.commit()
    return jsonify({"message": "Deleted"})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
