from flask import Flask, render_template, request
import email_analyzer

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        uploaded_file = request.files["raw_file"]
        raw_email = request.files["raw_file"].read()
        verdict, auth, frm, rply = email_analyzer.analyze_email(raw_email)
        print("File uploaded:", uploaded_file.filename)

        result = {
            "decision": verdict,
            "spf":  auth["SPF"],
            "dkim": auth["DKIM"],
            "dmarc": auth["DMARC"],
            "from": frm,
            "reply_to": rply
        }
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)          # http://127.0.0.1:5000
