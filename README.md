Email Analyzer Tool

A lightweight Python-based web application to analyze `.eml` email files for SPF, DKIM, and DMARC authentication, using Google-style validation logic and DNS-based lookups. This tool helps identify spoofed or suspicious emails by decoding their headers and verifying cryptographic signatures.

 Features

- Upload .eml files through a simple web interface
- Extract and display:
  - SPF result
  -DKIM result
  - DMARC result
  - `From`, `Reply-To`, `Return-Path` fields
- Real-time header preview
- Google DNS integration (`8.8.8.8`) for reliable DNS resolution
- MIME parsing and DKIM signature unfolding
- Domain alignment check for stricter verification
- 
 Dependencies
Install the required Python packages with:
bash
pip install flask spf dkimpy dnspython

 How to Run
Clone the repository:

bash
Copy
Edit
git clone https://github.com/yourusername/email-analyzer.git
cd email-analyzer
Install dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Start the Flask server:

bash
Copy
Edit
python app.py
