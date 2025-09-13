---
name: Bug report
about: Create a report to help us improve
title: '[BUG] Recon-WebUI crash on start'
labels: bug
assignees: ''
---

**Describe the bug**
When starting the web interface with `python web.py`, the application crashes with an `IndentationError` in one of the modules.

**To Reproduce**
Steps to reproduce the behavior:
1. Clone the repo and set up the virtual environment.
2. Run `pip install -r requirements.txt`.
3. Run `python web.py`.
4. See the error in the terminal.

**Expected behavior**
The Flask development server should start and allow me to access the Recon WebUI at `http://127.0.0.1:5000/`.

**Environment (please complete the following information):**
- **OS:** Kali Linux (latest rolling release, 2025)
- **Python version:** 3.11.2 (inside virtualenv)
- **Steps to reproduce:** run the app with `python web.py` after setup.

**Additional context**
This happened before we fixed the indentation in `app/__init__.py` and `app/routes.py`. After correcting indentation and re-running, the app worked fine.
