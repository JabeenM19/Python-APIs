# This is the integration of all 3 codes:
# app.py: which has basic flask app code
# database.py: which has flask app code with database integration
# tokens.py: which has flask app code with jwt

'''
To merge the functionalities from app.py, database.py, and tokens.py into a single app.py file, you'll integrate SQLAlchemy for database management and Flask-JWT-Extended for authentication.
'''
from flask import Flask , request,jsonify # imports for basic flask app
from flask_sqlalchemy import SQLAlchemy # imports for database integration
from flask_jwt_extended import JWTManager, create_access_token,jwt_required, get_jwt_identity # imports for jwt
import uuid
from werkzeug.security import generate_password_hash # imports for hashing passwords for signup
from datetime import datetime, timedelta

app = Flask(__name__)

#configure JWT and Database
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///expenses.db' # SQLite database URI
app.config['JWT_SECRET_KEY']='Jabin_key' # Your secret key for JWT

# Initialize SQLAlchemy and JWTManager
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Define the Expense model
class Expense(db.Model):
    id = db.Column(db.String(80), primary_key=True)
    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    user = db.Column(db.String(80), nullable=False)  # To associate expense with a user

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Create database tables
@app.before_first_request
def create_tables():
    db.create_all()

# Example route for debugging
@app.route('/example', methods=['POST'])
def example():
    return 'This route only allows POST method'

#Route for user sign-up
@app.route('/sign-up', methods=['POST'])
def signUp():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Validate input
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400

    # Check for existing user
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'Username already exists'}), 400

    # Hash the password
    hashed_password = generate_password_hash(password, method='sha256')

    # Create a new user
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User registered successfully'}), 201



# Route for user login to get JWT token
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    users = {'user1': 'password1'}  # Example user
    if username in users and users[username] == password:
        access_token = create_access_token(identity=username, expires_delta=timedelta(hours=2))
        return jsonify({'access_token': access_token}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

# API route for adding an expense, protected with JWT
@app.route('/add', methods=['POST'])
@jwt_required()
def add_expense():
    try:
        current_user = get_jwt_identity()
        data = request.get_json()
        category = data.get('category')
        if category not in ['Groceries', 'Leisure', 'Electronics', 'Utilities', 'Clothing', 'Health', 'Others']:
            return jsonify({'status': 'error', 'message': 'Invalid category'}), 400
        
        expense = Expense(
            id=str(uuid.uuid4()),
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            description=data['description'],
            amount=float(data['amount']),
            category=category,
            user=current_user
        )
        db.session.add(expense)
        db.session.commit()
        return jsonify({'status': 'success', 'expense': {
            'ID': expense.id,
            'Date': expense.date.strftime('%Y-%m-%d'),
            'Description': expense.description,
            'Amount': expense.amount,
            'Category': expense.category
        }}), 201
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

# API route for getting all expenses, protected with JWT
@app.route('/get', methods=['GET'])
@jwt_required()
def get_expense():
    current_user = get_jwt_identity()
    expenses = Expense.query.filter_by(user=current_user).all()
    return jsonify({'status': 'success', 'expenses': [{
        'ID': exp.id,
        'Date': exp.date.strftime('%Y-%m-%d'),
        'Description': exp.description,
        'Amount': exp.amount,
        'Category': exp.category
    } for exp in expenses]})

# API route for updating an expense, protected with JWT
@app.route('/update/<string:expense_id>', methods=['PUT'])
@jwt_required()
def update_expense(expense_id):
    current_user = get_jwt_identity()
    data = request.get_json()
    expense = Expense.query.get(expense_id)
    if expense and expense.user == current_user:
        try:
            if 'date' in data:
                expense.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
            if 'description' in data:
                expense.description = data['description']
            if 'amount' in data:
                expense.amount = float(data['amount'])
            if 'category' in data:
                expense.category = data['category']
            db.session.commit()
            return jsonify({'status': 'success', 'expense': {
                'ID': expense.id,
                'Date': expense.date.strftime('%Y-%m-%d'),
                'Description': expense.description,
                'Amount': expense.amount,
                'Category': expense.category
            }})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        return jsonify({'status': 'error', 'message': 'Expense not found or unauthorized'}), 404

# API route for deleting an expense, protected with JWT
@app.route('/delete/<string:expense_id>', methods=['DELETE'])
@jwt_required()
def delete_expense(expense_id):
    current_user = get_jwt_identity()
    expense = Expense.query.get(expense_id)
    if expense and expense.user == current_user:
        try:
            db.session.delete(expense)
            db.session.commit()
            return jsonify({'status': 'success', 'message': 'Expense deleted'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500
    else:
        return jsonify({'status': 'error', 'message': 'Expense not found or unauthorized'}), 404

if __name__ == '__main__':
    app.run(debug=True)

