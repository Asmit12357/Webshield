from flask import Flask,render_template,request
import sqlite3
from pycheck import run_checks
from score import calculate_score
from score import results

app=Flask(__name__,template_folder=".",static_folder=".")

def get_db():
    conn=sqlite3.connect("data.db")
    conn.row_factory=sqlite3.Row
    return conn

@app.route("/",methods=["GET","POST"])
def index():
    if request.method=="POST":
        url=request.form.get("url")
        scan_results=run_checks(url)
        score=calculate_score(scan_results)
        conn=get_db()
        conn.execute("INSERT INTO scans(url,score)VALUES(?,?)",(url,score))
        conn.commit()

        last_scans=conn.execute("SELECT url,score,timestamp FROM scans ORDER BY id DESC LIMIT 5").fetchall()

        return render_template("result.html",url=url,score=score,results=scan_results,last_scans=last_scans)
    return render_template("index.html")


@app.route("/history")
def history():
    conn=get_db()
    rows=conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    return render_template("history.html",rows=rows)
if __name__=="__main__":
   app.run(debug=True)
