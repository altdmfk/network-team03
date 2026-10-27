from flask import Flask, render_template


app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/login")
def login():
    return "로그인 화면은 다음 단계에서 연결할 예정입니다."


@app.get("/board")
def board():
    return "게시판은 다음 단계에서 연결할 예정입니다."


@app.get("/dashboard")
def dashboard():
    return "대시보드는 다음 단계에서 연결할 예정입니다."


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)
