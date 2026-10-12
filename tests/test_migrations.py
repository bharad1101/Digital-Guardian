"""
Digital Guardian - migration compatibility tests.

Runs the Alembic migration chain against a real temporary SQLite file and
asserts the resulting schema is compatible with the SQLAlchemy models
(regression test for the 0002 / user_settings.created_at drift).
"""

import pytest

from config import BASE_DIR

from app import create_app


@pytest.fixture()
def migrated_app(tmp_path):
    db_path = tmp_path / "migrated.db"
    app = create_app("testing")
    app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{db_path}"
    with app.app_context():
        yield app, db_path


def test_upgrade_to_head_produces_model_compatible_schema(migrated_app):
    from flask_migrate import upgrade

    app, db_path = migrated_app
    with app.app_context():
        upgrade(directory=str(BASE_DIR / "migrations"), revision="head")

        from extensions import db
        from models import User

        user = User(name="Migration Tester", email="migration@example.com")
        user.set_password("password123")
        db.session.add(user)
        db.session.flush()
        settings = user.ensure_settings()
        settings.notifications_enabled = False
        settings.retention_days = 7
        db.session.commit()

        # Re-read from the database to prove every model column exists.
        db.session.expire_all()
        again = db.session.get(User, user.id)
        assert again.email == "migration@example.com"
        assert again.settings is not None
        assert again.settings.save_history is True
        assert again.settings.notifications_enabled is False
        assert again.settings.retention_days == 7
        assert again.settings.created_at is not None
        assert again.settings.updated_at is not None
        assert again.scans.count() == 0