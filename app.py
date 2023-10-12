from flask import Flask, render_template, request
import my_prediction

app = Flask(__name__)


@app.route('/')
def login():
    return render_template('index.html')


@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']
    print(url)
    # Call your Python prediction function
    result,lst = my_prediction.pred(url)
    print(result)

    return render_template('result.html',
                           result=result,
                           url=url,
                           lst=lst[0])

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/team")
def team():
    return render_template("team.html")



if __name__ == '__main__':
    app.run(debug=True)
