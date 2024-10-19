from flask import Flask, render_template, abort

app = Flask(__name__)

@app.route("/")
def index():
    name = "jkhal"
    ipaddr = 0.0
    items = ["One", "Two", "Three!"]
    return render_template("index.html", name=name, ipaddr=ipaddr, items=items)

@app.route("/<path:file>")
def hello(file):
    if "~" in file or "//" in file or ".." in file:
        return render_template('403.html'), 403
    elif file.endswith(".html"):
        try:
            return render_template(file), 200
        except:
            return render_template('404.html'), 404
    else:
        return render_template('404.html'), 404

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5001)
