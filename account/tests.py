from django.test import TestCase
from django.urls import reverse
from django.contrib.auth import get_user_model
from .forms import UserRegistrationForm
from django.middleware.csrf import _get_new_csrf_string
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.auth import get_user_model



class UserRegistrationTest(TestCase):
    def setUp(self):
        self.registration_url = reverse('register') 
        self.user_data = {
            'email': 'newuser@email.com',
            'password': 'newpassword123',
            'password2': 'newpassword123',
        }

    def test_register_view_form_valid(self):
        response = self.client.post(self.registration_url, self.user_data)
        self.assertEqual(response.status_code, 302)  # Expect a redirect after successful registration

        # Check if a new user has been created with the provided email
        self.assertTrue(get_user_model().objects.filter(email=self.user_data['email']).exists())

    def test_register_view_form_invalid(self):
        # Test with invalid data (e.g., missing email)
        invalid_data = {
            'password': 'newpassword123',
            'password2': 'newpassword123',
        }
        response = self.client.post(self.registration_url, invalid_data)
        self.assertEqual(response.status_code, 200)  # Expect a form validation error

        # Ensure that no new user has been created
        self.assertFalse(get_user_model().objects.filter(email=self.user_data['email']).exists())

    def test_register_view_form_password_mismatch(self):
        # Test with password mismatch
        self.user_data['password2'] = 'differentpassword123'
        response = self.client.post(self.registration_url, self.user_data)
        self.assertEqual(response.status_code, 200)  # Expect a form validation error

        # Ensure that no new user has been created
        self.assertFalse(get_user_model().objects.filter(email=self.user_data['email']).exists())

    def test_register_view_uses_correct_template(self):
        response = self.client.get(self.registration_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'account/register.html')

class UserLoginLogoutTest(TestCase):
    def setUp(self):
        self.login_url = reverse('login') 
        self.logout_url = reverse('logout')

        # Create a test user
        self.user_data = {
            'email': 'testuser@email.com',
            'password': 'mypassword123',
        }
        self.user = get_user_model().objects.create_user(**self.user_data)

    def test_user_login_valid(self):
        response = self.client.post(self.login_url, self.user_data)
        self.assertEqual(response.status_code, 302)  # Expect a redirect after successful login

        # Check if the user is authenticated
        self.assertTrue(response.wsgi_request.user.is_authenticated)

    def test_user_login_invalid(self):
        # Test with invalid login credentials
        invalid_data = {
            'email': 'testuser@email.com',
            'password': 'wrongpassword',
        }
        response = self.client.post(self.login_url, invalid_data)
        self.assertEqual(response.status_code, 200)  # Expect a form validation error

        # Ensure that the user is not authenticated
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_user_logout(self):
        # Log in the user first
        self.client.login(email=self.user_data['email'], password=self.user_data['password'])

        response = self.client.get(self.logout_url)
        self.assertEqual(response.status_code, 302)  # Expect a redirect after successful logout

        # Ensure that the user is not authenticated after logout
        self.assertFalse(response.wsgi_request.user.is_authenticated)

    def test_view_uses_correct_template(self):
        response = self.client.get(reverse('login'))
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, 'account/login.html')


class HomepageAccessTest(TestCase):
    def setUp(self):
        # Create a test user
        self.user_data = {
            'email': 'testuser@email.com',
            'password': 'mypassword123',
        }
        self.user = get_user_model().objects.create_user(**self.user_data)

        # URL for the homepage view
        self.homepage_url = reverse('homepage') 

    def test_unauthenticated_user_redirected_to_login(self):
        response = self.client.get(self.homepage_url)
        self.assertEqual(response.status_code, 302)  # Expect a redirect (status code 302)
        self.assertRedirects(response, reverse('login') + '?next=%2Faccount%2F')  # Ensure redirection to the login page

    def test_authenticated_user_can_access_view(self):
        # Log in the user first
        self.client.login(email=self.user_data['email'], password=self.user_data['password'])

        response = self.client.get(self.homepage_url)
        self.assertEqual(response.status_code, 200)  # Expect a successful response (status code 200)


class AuthenticationErrorHandlingTest(TestCase):
    def setUp(self):
        # URL for the login view
        self.login_url = reverse('login')

        # Test user data
        self.user_data = {
            'email': 'testuser@email.com',
            'password': 'mypassword123',
        }

        # Create a test user
        self.user = get_user_model().objects.create_user(**self.user_data)

    def test_incorrect_password(self):
        # Attempt login with an incorrect password
        incorrect_data = {
            'email': 'testuser@email.com',
            'password': 'incorrect_password',
        }
        response = self.client.post(self.login_url, incorrect_data)
        self.assertEqual(response.status_code, 200)  # Expect a form validation error
        self.assertFalse(response.wsgi_request.user.is_authenticated)  # User should not be authenticated

    def test_non_existent_user(self):
        # Attempt login with a non-existent user
        non_existent_data = {
            'email': 'non_existent@email.com',
            'password': 'mypassword123',
        }
        response = self.client.post(self.login_url, non_existent_data)
        self.assertEqual(response.status_code, 200)  # Expect a form validation error
        self.assertFalse(response.wsgi_request.user.is_authenticated)  # User should not be authenticated




# class CSRFAttackTest(TestCase):
#     def setUp(self):
#         self.login_url = reverse('login')
#         self.user_data = {
#             'email': 'testuser@email.com',
#             'password': 'mypassword123',
#         }
#         self.user = get_user_model().objects.create_user(**self.user_data)

#     def test_csrf_attack_prevention(self):
#         # Log in the user
#         self.client.login(email=self.user_data['email'], password=self.user_data['password'])

#         # Generate a forged CSRF token (different from the actual token)
#         forged_csrf_token = _get_new_csrf_string()

#         # carry out a POST request with the forged CSRF token
#         response = self.client.post(self.login_url, {'email': 'attacker@example.com', 'password': 'attackerpassword', 'csrfmiddlewaretoken': forged_csrf_token}, HTTP_REFERER='http://malicious-site.com')

#         print(response.status_code)
#         print(response.content)

#         # Ensure that the request is denied (status code 403)
#         self.assertEqual(response.status_code, 403)


class SessionsFixationTest(TestCase):
    def test_session_fixation_prevention(self):
        # Create a user
        User = get_user_model()
        user_data = {'email': 'testuser@email.com', 'password': 'mypassword123'}
        user = User.objects.create_user(**user_data)

        # Log in as the user and get the session ID
        login_url = reverse('login')
        self.client.login(email=user_data['email'], password=user_data['password'])
        session_id_before_login = self.client.session.session_key

        # Log out to end the current session
        logout_url = reverse('logout')
        self.client.get(logout_url)

        # Log in again and get the new session ID
        self.client.login(email=user_data['email'], password=user_data['password'])
        session_id_after_login = self.client.session.session_key

        # Ensure that the session ID changes after login
        self.assertNotEqual(session_id_before_login, session_id_after_login)

class CSRFValidationTest(TestCase):
    def test_csrf_validation(self):
        # Generate a CSRF token
        response = self.client.get(reverse('login'))
        csrf_token = response.cookies['csrftoken'].value

        # Simulate a POST request with a forged CSRF token
        login_url = reverse('login')
        response = self.client.post(
            login_url,
            {'email': 'attacker@example.com', 'password': 'attackerpassword', 'csrfmiddlewaretoken': csrf_token},
            HTTP_REFERER='http://malicious-site.com'
        )

        # Ensure that the response contains an error message
        error_message_present = 'Invalid email or password' in str(response.content)

        # Assert that the error message is present
        self.assertTrue(error_message_present)