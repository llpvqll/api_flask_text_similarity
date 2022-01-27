from flask import Flask, jsonify, request
from flask_restful import Resource, Api
import bcrypt
from pymongo import MongoClient
import spacy


app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://db:27017")
db = client.SimilarityDB
users = db["Users"]


def user_exist(username):
    if users.count_documents({"Username": username}) == 0:
        return False
    else:
        return True


class Register(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data['username']
        password = posted_data['password']

        if user_exist(username):
            ret_json = {
                'status': 301,
                'msg': 'Invalid Username'
            }
            return jsonify(ret_json)

        hashed_pw = bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())

        users.insert_one({
            'Username': username,
            'Password': hashed_pw,
            'Tokens': 6
        })

        ret_json = {
            'status': 200,
            'msg': "You've successfully signed up to the API"
        }
        return jsonify(ret_json)


def verify_pw(username, password):
    if not user_exist(username):
        return False

    hashed_pw = users.find({
        "Username": username,
    })[0]["Password"]

    if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
        return True
    else:
        return False


def count_token(username):
    tokens = users.find({
        'Username': username
    })[0]['Tokens']
    return tokens


class Detect(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data['username']
        password = posted_data['password']
        text1 = posted_data['text1']
        text2 = posted_data['text2']

        if not user_exist(username):
            ret_json = {
                'status': 301,
                'msg': "Invalid Username"
            }
            return jsonify(ret_json)

        correct_pw = verify_pw(username, password)

        if not correct_pw:
            ret_json = {
                'status': 302,
                "msg": "Invalid Password"
            }
            return jsonify(ret_json)

        num_token = count_token(username)

        if num_token <= 0:
            ret_json = {
                'status': 303,
                'msg': "You're out of tokens, please refill!"
            }
            return jsonify(ret_json)

        # calculate the edit distance
        spacy.prefer_gpu()
        nlp = spacy.load("en_core_web_sm", disable=['tagger', 'ner'])

        text1 = nlp(text1)
        text2 = nlp(text2)

        # ratio is a number between 0 and 1 the closer to 1, the more similar text1 and text2 are
        ratio = text1.similarity(text2)
        ret_json = {
            'status': 200,
            'similarity': ratio,
            'msg': "Similarity score calculated successfully!"
        }
        current_tokens = count_token(username)

        users.update_one({
            'Username': username,

        }, {
            "$set":{
                'Tokens': current_tokens-1
            }
        })

        return jsonify(ret_json)


class Refill(Resource):
    def post(self):
        posted_data = request.get_json()

        username = posted_data['username']
        password = posted_data['admin_pw']
        refill_amount = posted_data['refill']

        if not user_exist(username):
            ret_json = {
                'status': 301,
                'msg': 'Invalid Username'
            }
            return jsonify(ret_json)

        correct_pw = "abc123"
        if not password == correct_pw:
            ret_json = {
                'status': 304,
                'msg': "Invalid admin password"
            }
            return jsonify(ret_json)

        current_tokens = count_token(username)
        users.update_one({
            "Username": username
        }, {
            "$set": {
                "Tokens": refill_amount
            }
        })
        ret_json = {
            'status': 200,
            'msg': "Refilled successfully!"
        }
        return jsonify(ret_json)


api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refill, '/refill')

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)





