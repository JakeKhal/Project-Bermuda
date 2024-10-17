from flask import Flask, render_template, abort

app = Flask(__name__)

@app.route("/<path:file>")
def hello(file):
    if "~" in file or "//" in file or ".." in file:
        abort(403)
    elif file.endswith(".html"):
        try:
            return render_template(file),200
        except:
            abort(404)
    else:
        abort(404)

if __name__ == "__main__":
    app.run(debug=True)

@app.errorhandler(404)
def error_404(error):
    return render_template('404.html'),404

@app.errorhandler(403)
def error_403(error):
    return render_template('403.html'),403

if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0')