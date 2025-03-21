from flask import Flask, request, jsonify
import threading
import json
import requests
import jwt
import datetime as dt

app = Flask(__name__)

SECRET_KEY = bytes.fromhex("828691b81bdb1caf0d0b696f47b55936")

def generate_jwt(token: str, account_id: int) -> str:
    headers = {
        "alg": "HS256",
        "typ": "JWT",
        "svr": "1"
    }

    payload = {
        "account_id": account_id,
        "token": token,
        "nickname": "vex1.phần.phần.phần",
        "not_region": "VN",
        "local_region": "VN",
        "external_id": "c3919c19b82eabada01742949d0b4b30",
        "external_type": 4,
        "plat_id": 1,
        "client_version": "1.104.6",
        "external_source": 0,
        "country_code": "VN",
        "user_version": 1,
        "release_version": "OB47",
        "exp": dt.datetime.utcnow() + dt.timedelta(hours=1)
    }

    jwt_token = jwt.encode(payload, SECRET_KEY, algorithm="HS256", headers=headers)
    return jwt_token

def decode_jwt(jwt_token: str):
    try:
        decoded = jwt.decode(jwt_token, SECRET_KEY, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        return {"error": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"error": "Invalid token"}

class FF_CLIENT(threading.Thread):
    def __init__(self, id, password):
        super().__init__()
        self.id = id
        self.password = password
        self.result = {}

    def run(self):
        self.get_token()

    def guest_token(self):
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{self.id}",
            "password": f"{self.password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067",
        }
        response = requests.post(url, headers=headers, data=data)
        return response.json()

    def get_token(self):
        try:
            token_data = self.guest_token()
            if "access_token" in token_data:
                jwt_token = generate_jwt(token_data["access_token"], self.id)
                decoded_jwt = decode_jwt(jwt_token)
                self.result = {
                    'id': self.id,
                    'token_data': token_data,
                    'jwt_token': jwt_token,
                    'decoded_jwt': decoded_jwt,
                }
            else:
                self.result = {'error': 'Token not found'}
        except Exception as e:
            self.result = {'error': str(e)}

@app.route('/get_player_data', methods=['GET'])
def get_player_data():
    player_id = request.args.get('uid')
    password = request.args.get('pass')

    if not player_id or not password:
        return jsonify({'error': 'Missing uid or pass'}), 400

    client = FF_CLIENT(player_id, password)
    client.start()
    client.join()

    return jsonify(client.result)

if __name__ == '__main__':# your port here
    app.run(debug=True, host='0.0.0.0', port=5000)
  
