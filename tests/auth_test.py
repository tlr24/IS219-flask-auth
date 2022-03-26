"""This test the authorization functionalities"""
from flask import session
import pytest
from app.db.models import User
# pylint: disable=line-too-long

def test_request_main_menu_links(client):
    """This makes the index page"""
    response = client.get("/")
    assert response.status_code == 200
    assert b'href="/login"' in response.data
    assert b'href="/register"' in response.data

def test_auth_pages(client):
    """This makes the index page"""
    response = client.get("/dashboard")
    assert response.status_code == 302
    response = client.get("/register")
    assert response.status_code == 200
    response = client.get("/login")
    assert response.status_code == 200

def test_successful_register(client):
    """Tests successful registration"""
    assert client.get("register").status_code == 200
    response = client.post("register", data={"email": "a@a.com", "password": "12345678", "confirm": "12345678"}) # "csrf_token": {{session['csrf_token']}}
    assert "http://localhost/login" == response.headers["Location"]

    # test that the user was inserted into the database
    with client.application.app_context():
        assert User.query.filter_by(email="a@a.com").first() is not None

def test_successful_login(client):
    """Tests successful login"""
    # test that viewing the page renders without template errors
    assert client.get("/login").status_code == 200

    # test that successful login redirects to the index page
    response = client.post("/login", data={"email": "a@a.com", "password": "12345678"})
    assert response.headers["Location"] == "http://localhost/dashboard"

    with client.application.app_context():
        user_id = User.query.filter_by(email="a@a.com").first().get_id()

    # login request set the user_id in the session
    # check that the user is loaded from the session
    with client:
        client.get("/")
        assert session["_user_id"] == user_id
        #assert g.user["username"] == "a@a.com"

@pytest.mark.parametrize(
    ("email", "password", "message"),
    (("a@a.com", "test1234", b"Invalid username or password"), ("a", "12345678", b"Invalid username or password")),
)
def test_login_validate_input(client, email, password, message):
    """Test logging in with both invalid email and password"""
    response = client.post("/login", data={"email": email, "password": password}, follow_redirects=True)
    assert message in response.data

def test_register_bad_email(client):
    """Test registering with a bad email"""
    response = client.post("/register", data={"email": "", "password": "12345678", "confirm": "12345678"}, follow_redirects=True)
    # check for status code to be 200 instead of 302, meaning it didn't redirect (didn't pass frontend validation)
    assert response.status_code == 200
    # added 302 to register() redirects in auth/__init__.py to make sure we get the redirect status code

def test_register_password_confirmation(client):
    """Test password confirmation by registering with mismatching passwords"""
    response = client.post("/register", data={"email": "t@a.com", "password": "12345678", "confirm": "87654321"}, follow_redirects=True)
    assert b"Passwords must match" in response.data

def test_already_registered(client):
    """Tests if user already registered"""
    assert client.get("register").status_code == 200
    response = client.post("register", data={"email": "a@a.com", "password": "12345678", "confirm": "12345678"}) # "csrf_token": {{session['csrf_token']}}
    assert "http://localhost/login" == response.headers["Location"]
    with client:
        response_2 = client.get("/login")
        assert b"Already Registered" in response_2.data

def test_dashboard_access(client):
    """Tests allowing access to the dashboard for logged-in users"""
    client.post("/login", data={"email": "a@a.com", "password": "12345678"}, follow_redirects=True)
    assert client.get("/dashboard").status_code == 200

def test_logout(client):
    """Testing logging out"""
    client.post("/login", data={"email": "a@a.com", "password": "12345678"}, follow_redirects=True)
    with client:
        client.get("/logout")
        assert "_user_id" not in session

def test_denied_dashboard_access(client):
    """Testing denying access to the dashboard for not logged-in users"""
    response = client.get("/dashboard")
    assert "http://localhost/login?next=%2Fdashboard" == response.headers["Location"]
    with client:
        response = client.get("/login")
        assert b"Please log in to access this page." in response.data
