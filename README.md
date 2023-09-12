# django-authentication-task

This project is a Django-based application that implements user authentication and includes tests to evaluate its security and functionality. Follow the instructions below to set up the project and run the tests for evaluation.

## Prerequisites

Before you begin, ensure that you have the following installed:

- Python 3.x
- Django 4.x (or the compatible version)
- Python virtual environment (recommended)

## Setup Instructions

1. Clone the Repository:

   ```bash
   git clone repo
   cd django-authentication-task
2. Create and Activate a Virtual Environment:
   python3 -m venv venv
   source venv/bin/activate
3. Install Dependencies:
   pip install -r requirements.txt
4. Create a .env File:
   Create a .env file in the project root directory.
   Add your Django SECRET_KEY to the .env file:
   SECRET_KEY=your_secret_key_here
5. Apply Database Migrations:
   python manage.py migrate
6. Run the Development Server:
   python manage.py runserver

## Running the Tests
To run the tests for the authentication system and evaluate its security and functionality, follow these steps:

1. Ensure that the development server is running.

2. Open a new terminal window (if the virtual environment is active) or activate the virtual environment again:
   source venv/bin/activate
3. Run the tests using Django's test runner:
   python manage.py test account.tests
   python manage.py test account.tests
