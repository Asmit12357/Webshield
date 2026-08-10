import sqlite3
def calculate_score(results):
    score=0
    if results["https"]:
        score+=25
    if results["hsts"]:
        score+=15
    for value in results["headers"].values():
        if value:
            score+=5
    if results["ssl_certificate"]:
        score+=20
    if results["cookie_security"]:
        score+=10
    if results["server_leakage"]:
        score+=10
    return score
def results():
    conn=sqlite3.connect("data.db")
    c=conn.cursor()
    c.execute("SELECT url,score,timestamp FROM record ORDER BY id DESC LIMIT 5")
    results=c.fetchall()
    conn.close()
    return results


