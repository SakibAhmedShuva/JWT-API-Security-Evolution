from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Configure JWT
app.config['JWT_SECRET_KEY'] = 'your-secret-key'  # Change this to a secure random key
jwt = JWTManager(app)

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
def login():
    """
    User login endpoint
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if user exists and password is correct
    if username not in users or not check_password_hash(users[username]['password'], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Create access token
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token), 200

@app.route('/calculate', methods=['POST'])
@jwt_required()  # Protect this route with JWT
def calculate():
    """
    Calculate endpoint with JWT protection
    """
    # Verify the user's identity
    current_user = get_jwt_identity()

    # Get JSON data from request
    data = request.get_json()
    operation = data.get("operation")
    num1 = data.get("num1")
    num2 = data.get("num2")

    # Perform operations
    if operation == "add":
        result = num1 + num2
    elif operation == "subtract":
        result = num1 - num2
    elif operation == "multiply":
        result = num1 * num2
    elif operation == "divide":
        if num2 == 0:
            return jsonify({"error": "Division by zero is not allowed"}), 400
        result = num1 / num2
    else:
        return jsonify({"error": "Invalid operation"}), 400

    return jsonify({
        "result": result, 
        "calculated_by": current_user
    })

if __name__ == '__main__':
    app.run(debug=True, port=5102)