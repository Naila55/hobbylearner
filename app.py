from flask import Flask, render_template, request
import email_analyzer  # your new email_analyzer.py

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        raw_file = request.files["raw_file"]
        raw_email = raw_file.read()

        # Call analyzer (only raw email needed now!)
        decision, auth_result, from_email, reply_to_email = email_analyzer.analyze_email(raw_email)

        result = {
            "decision": decision,
            "spf": auth_result["SPF"],
            "dkim": auth_result["DKIM"],
            "dmarc": auth_result["DMARC"],
            "from": from_email,
            "reply_to": reply_to_email
        }

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
