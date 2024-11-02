from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash
from datetime import timedelta
import os
from dotenv import load_dotenv
import logging
from logging.handlers import RotatingFileHandler
import numbers
from functools import wraps

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configure JWT with environment variables
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'default-key-for-development-only')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
jwt = JWTManager(app)

# Configure logging
if not os.path.exists('logs'):
    os.mkdir('logs')
file_handler = RotatingFileHandler('logs/calculator.log', maxBytes=10240, backupCount=10)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Calculator startup')

# HTTPS enforcement
def require_https():
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_secure and not app.debug:
                return jsonify({"error": "HTTPS required"}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Input validation
def validate_calculation_input(data):
    if not all(key in data for key in ['operation', 'num1', 'num2']):
        return False, "Missing required fields"
    
    if not isinstance(data['operation'], str):
        return False, "Operation must be a string"
    
    if data['operation'] not in ['add', 'subtract', 'multiply', 'divide']:
        return False, "Invalid operation"
    
    if not all(isinstance(data[key], numbers.Number) for key in ['num1', 'num2']):
        return False, "Numbers must be numeric values"
    
    return True, None

# Predefined users with hashed passwords
# Simulated user database (replace with a real database in production)
users = {
    'abil': {
        'password': 'scrypt:32768:8:1$tiwMQ71CnRbrHq3H$d92008ab04087be0e34d53823fa2f823522b0db927074865d92b4c41538d7b7549feda2b661f03e96d67f93e2f88587a546e057f779e382f6cb6caf08f400681',
        'roles': ['user']
    },
    'chaka': {
        'password': 'scrypt:32768:8:1$dBBUiOYEP90fi6hg$1400a638f630d147dee32683c8b49cb31139a03a5ffd1226db456e13958953106826a24db1dd4401e72b0ab5caa84ec9d6cc470fb74f55ce541fd8b985b744a9',
        'roles': ['admin']
    }
}

@app.route('/login', methods=['POST'])
@require_https()
def login():
    """
    User login endpoint that provides both access and refresh tokens
    """
    try:
        data = request.get_json()
        if not data or 'username' not in data or 'password' not in data:
            app.logger.warning('Login attempt with missing credentials')
            return jsonify({"error": "Missing credentials"}), 400

        username = data['username']
        password = data['password']

        # Check if user exists and password is correct
        if username not in users or not check_password_hash(users[username]['password'], password):
            app.logger.warning(f'Failed login attempt for user: {username}')
            return jsonify({"error": "Invalid credentials"}), 401

        # Create both access and refresh tokens
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        
        app.logger.info(f'Successful login for user: {username}')
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200
    except Exception as e:
        app.logger.error(f'Login error: {str(e)}')
        return jsonify({"error": "Internal server error"}), 500

@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@require_https()
def refresh():
    """
    Endpoint to refresh the access token using a refresh token
    """
    try:
        current_user = get_jwt_identity()
        new_access_token = create_access_token(identity=current_user)
        app.logger.info(f'Token refreshed for user: {current_user}')
        return jsonify({'access_token': new_access_token}), 200
    except Exception as e:
        app.logger.error(f'Token refresh error: {str(e)}')
        return jsonify({"error": "Internal server error"}), 500

@app.route('/calculate', methods=['POST'])
@jwt_required()
@require_https()
def calculate():
    """
    Calculate endpoint with JWT protection and input validation
    """
    try:
        # Verify the user's identity
        current_user = get_jwt_identity()
        
        # Get JSON data from request
        data = request.get_json()
        if not data:
            app.logger.warning(f'Invalid request data from user: {current_user}')
            return jsonify({"error": "Invalid request data"}), 400

        # Validate input
        is_valid, error_message = validate_calculation_input(data)
        if not is_valid:
            app.logger.warning(f'Input validation failed for user {current_user}: {error_message}')
            return jsonify({"error": error_message}), 400

        operation = data["operation"]
        num1 = data["num1"]
        num2 = data["num2"]

        # Perform operations
        if operation == "add":
            result = num1 + num2
        elif operation == "subtract":
            result = num1 - num2
        elif operation == "multiply":
            result = num1 * num2
        elif operation == "divide":
            if num2 == 0:
                app.logger.warning(f'Division by zero attempted by user: {current_user}')
                return jsonify({"error": "Division by zero is not allowed"}), 400
            result = num1 / num2

        app.logger.info(f'Calculation performed by user {current_user}: {operation} {num1} {num2} = {result}')
        return jsonify({
            "result": result, 
            "calculated_by": current_user
        })

    except Exception as e:
        app.logger.error(f'Calculation error: {str(e)}')
        return jsonify({"error": "Internal server error"}), 500

if __name__ == '__main__':
    # Only enable debug mode in development
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    app.run(debug=debug_mode, port=5102, ssl_context='adhoc')  # Enable HTTPS in development