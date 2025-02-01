# Basic Flask App

A simple Flask web application featuring user registration and login functionality. This app demonstrates secure password storage following best security practices.

## Installation

To install the required dependencies, run:

```
pip install -r requirements.txt
```

## Usage

1. Open a terminal and execute:
   ```
   ./Run.sh
   ```
2. Navigate to https://127.0.0.1:5000/ in your web browser
3. Accept the self-signed certificate in the security pop-up
4. You will be redirected to the home page

## Project Structure

```
.
├── app.py
├── requirements.txt
├── Run.sh
├── static
│   └── css
│       └── main.css
├── templates
│   ├── 404.html
│   ├── 500.html
│   ├── dashboard.html
│   ├── home.html
│   ├── login.html
│   └── register.html
└── users.db
```

Note: The `users.db` SQLite database will be created automatically when the app is run for the first time.

## Features

- User registration
- Secure login system
- Password hashing for enhanced security
- Basic dashboard for logged-in users
- Custom error pages (404 and 500)

## Security

This application implements best practices for password storage, including:
- Secure hashing algorithms
- Salting of passwords
- Protection against common vulnerabilities

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the [MIT License](LICENSE).
