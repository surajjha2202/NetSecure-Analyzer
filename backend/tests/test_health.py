from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_health():
    response = client.get("/api/health")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["service"] == "NetSecure Analyzer"
    assert data["version"] == "1.0.0"

def test_database_health():
    response = client.get("/api/health/database")

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "healthy"
    assert data["database"] == "postgresql"
    assert data["connection"] is True
    assert data["test_query"] == 1
