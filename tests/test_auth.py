import os
os.environ["DATABASE_URL"] = "sqlite:///./test.db"

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root():
    r = client.get("/")
    assert r.status_code == 200
    assert "message" in r.json()


def test_register_and_login():
    payload = {
        "email": "test@example.com",
        "username": "testuser",
        "full_name": "Test User",
        "password": "StrongPass1!",
    }
    r = client.post("/api/v1/auth/register", json=payload)
    assert r.status_code in (201, 400)

    login = client.post(
        "/api/v1/auth/login/json",
        json={"email": "test@example.com", "password": "StrongPass1!"},
    )
    assert login.status_code == 200
    data = login.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_weak_password_rejected():
    payload = {
        "email": "weak@example.com",
        "username": "weakuser",
        "password": "weakpass",
    }
    r = client.post("/api/v1/auth/register", json=payload)
    assert r.status_code == 422
