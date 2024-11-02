# JWT API Security Evolution

A comprehensive demonstration of evolving API security implementations using JWT (JSON Web Token) authentication in Flask, from basic to production-ready approaches. This repository uses a simple calculator API as an example to showcase different levels of security implementation.

## 📋 Overview

This repository serves as an educational resource demonstrating the progressive implementation of API security using JWT authentication. It showcases three different security levels, making it perfect for developers looking to understand how to properly secure their APIs using industry best practices.

## 🔑 Key Security Features

- Comprehensive JWT authentication implementation
- Access and refresh token mechanism
- Role-based access control (RBAC)
- Secure password hashing with Werkzeug
- Request validation and sanitization
- HTTPS enforcement
- Advanced logging and monitoring
- Environment-based configuration

## 🗂 Repository Structure

```
.
├── calculator_no_security.py      # Base API implementation without security
├── calculator_basic_security.py   # Basic JWT security implementation
├── calculator_secure++.py         # Production-ready secure implementation
├── password_generator.ipynb       # Password hash generation utility
└── requirements.txt              # Project dependencies
```

## 📁 Security Implementation Levels

### Level 1: No Security (calculator_no_security.py)
Base implementation demonstrating:
- Basic REST API structure
- Raw endpoint exposure
- Why security is needed
- Common vulnerabilities in unsecured APIs

### Level 2: Basic JWT Security (calculator_basic_security.py)
Introduces fundamental security concepts:
- Basic JWT implementation
- Protected routes using decorators
- User authentication
- Password hashing
- Basic error handling

### Level 3: Production Security (calculator_secure++.py)
Production-grade security implementation featuring:
- Advanced JWT with refresh token mechanism
- Comprehensive request validation
- Secure headers and HTTPS enforcement
- Environment-based configuration
- Detailed logging and monitoring
- Error handling and security best practices
- Role-based access control

### Utilities

#### password_generator.ipynb
- Demonstrates secure password hashing
- Uses Werkzeug security features
- Shows proper password storage practices

#### requirements.txt
Essential security-related dependencies:
- Flask 3.0.3
- Flask-JWT-Extended 4.6.0
- PyJWT 2.9.0
- python-dotenv 1.0.1
- Werkzeug 3.1.1

## 🚀 Getting Started

1. Clone the repository:
```bash
git clone https://github.com/yourusername/jwt-api-security-evolution.git
cd jwt-api-security-evolution
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables (for secure++ version):
```bash
export JWT_SECRET_KEY='your-secret-key'
export FLASK_ENV='development'
```

5. Run desired implementation:
```bash
python calculator_secure++.py
```

## 🔒 Authentication Examples

### User Authentication
```bash
POST /login
Content-Type: application/json

{
    "username": "your_username",
    "password": "your_password"
}
```

### Protected Endpoint Access
```bash
POST /calculate
Authorization: Bearer <your_jwt_token>
Content-Type: application/json

{
    "operation": "add",
    "num1": 10,
    "num2": 5
}
```

## 🔐 Security Implementation Details

### JWT Implementation
- Access tokens with configurable expiry
- Refresh token mechanism
- Token blacklisting capability
- Secure token handling

### Authentication Features
- Secure password hashing
- Role-based access control
- User session management
- Failed login attempt handling

### API Security
- Input validation and sanitization
- HTTPS enforcement
- Secure headers
- Rate limiting preparation
- Comprehensive error handling

## ⚠️ Production Considerations

- Replace default JWT secret key
- Implement rate limiting
- Enable HTTPS
- Set up proper monitoring
- Configure secure headers
- Implement proper session management
- Add security audit logging

## 📄 License

This project is open source and available under the MIT License - see the [LICENSE](LICENSE) file for details. Feel free to use this project for learning and development purposes.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check [issues page](../../issues).

## 📚 Additional Resources

- [JWT Best Practices](https://datatracker.ietf.org/doc/html/rfc8725)
- [Flask Security Documentation](https://flask.palletsprojects.com/en/2.0.x/security/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Flask-JWT-Extended Documentation](https://flask-jwt-extended.readthedocs.io/)
