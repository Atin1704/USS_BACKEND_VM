# USS_BACKEND_VM (Django)

This repository contains a minimal Django project scaffold so you can start adding code.

Quick setup (macOS / zsh):

1. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

3. Set an environment variable for the Django secret key (or create a `.env` file):

```bash
export DJANGO_SECRET_KEY='change-this-to-a-secure-key'
```

4. Run migrations and start the dev server:

```bash
python manage.py migrate
python manage.py runserver
```

Project layout:

- `uss_backend/` - Django project package (settings, urls, wsgi/asgi)
- `core/` - starter app for your code

If you want, I can also create a development `Makefile`, Dockerfile, or set up pre-commit hooks. What would you like next?
