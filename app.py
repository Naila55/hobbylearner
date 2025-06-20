from flask import Flask, render_template, request
import email_analyzer

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    filename = None
    if request.method == "POST":
        uploaded_file = request.files["raw_file"]
        filename = uploaded_file.filename
        raw_email =  uploaded_file.read()
        verdict, auth, frm, rply, rtnpath = email_analyzer.analyze_email(raw_email)

        print("File uploaded:", uploaded_file.filename)

        result = {
            "decision": verdict,
            "spf":  auth["SPF"],
            "dkim": auth["DKIM"],
            "dmarc": auth["DMARC"],
            "from": frm,
            "reply_to": rply,
            "return_path": rtnpath
        }
    return render_template("index.html", result=result, filename=filename)



app.run(port=5600,host="0.0.0.0")
