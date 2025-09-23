This folder contains a Python file with an unsafe deserialization.

If you’d like to test the vulnerability, clone this repo or copy this folder onto your machine, move to this folder and then run:
```bash
python -m venv venv
source venv/bin/activate
pip install gradio
python example.py
```
This will start a new Gradio app.

To run the CodeQL queries in this repo, you'll need VS Code with the [CodeQL extension](https://marketplace.visualstudio.com/items?itemName=GitHub.vscode-codeql) installed.

Alternatively, you can use the [VS Code CodeQL starter workspace](https://github.com/github/vscode-codeql-starter) if you want to get started with writing your own queries for any language supported by CodeQL: Javascript, Ruby, Java, C/C++ etc.
