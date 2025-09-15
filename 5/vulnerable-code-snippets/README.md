This folder contains a Python file with an unsafe deserialization.

If you’d like to test the vulnerability, clone this repo or copy this folder onto your machine, move to this folder and then run:
```bash
python -m venv venv
source venv/bin/activate
pip install gradio
python example.py
```
This will start a new Gradio app.

To run the CodeQL queries in this repo, you'll need a [VS Code CodeQL starter workspace](https://github.com/github/vscode-codeql-starter).
