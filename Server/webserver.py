from ast import Import
import json
from flask import Flask
from flask import request
import sql
import log
import rule
import config
from flask import Flask, render_template, request, jsonify

app = Flask(__name__,
            template_folder="./templates",
            static_folder="./templates",
            static_url_path="")
app.jinja_env.variable_start_string = '{.<'
app.jinja_env.variable_end_string = '>.}'


@app.route('/')
def root():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    return render_template("index.html")


@app.route('/static/<path:path>')
def on_vue_static(path):
    print(path)
    return app.send_static_file("./" + path)


@app.route('/api/v1/get/process_chain/delete', methods=['GET'])
def delete_chain_data():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    id = request.args.get('id')
    return_data = {'success': 1}
    if id is not None:
        sql.delete_threat(id)
    return {'data': return_data}


@app.route('/api/v1/get/process_chain/pull', methods=['GET'])
def pull_chain_data():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    id = request.args.get('id')
    return_data = {}
    if id is not None:
        threat_data = sql.query_one_threat(id)
        return_data = {
            'host': threat_data[1],
            'chain_hash': threat_data[2],
            'type': threat_data[3],
            'risk_score': threat_data[4],
            'hit_rule': json.loads(threat_data[5]),
            'chain': json.loads(threat_data[6]),
            'is_end': threat_data[7]
        }
    return {'data': return_data}


@app.route('/api/v1/get/process_chain/all')
def process_chain():
    if request.remote_addr not in config.ALLOW_ACCESS_IP:
        return "Access Denied"
    threat_datas = sql.query_all_threat_log()
    return_data = []
    for iter in threat_datas:
        return_data.append({
            'host': iter[0],
            'chain_hash': iter[1],
            'hit_rule': json.loads(iter[2]),
            'time': iter[3],
            'type': iter[4],
            'risk_score': iter[5],
            'id': iter[6],
            'is_end': iter[7],
            'start_process': json.loads(iter[8]),
        })
    return {'data': return_data}


@app.route('/api/v1/process', methods=['POST'])
def process():
    if request.method == 'POST':
        # print(request.data)
        body_data = request.data.decode()
        # 转小写
        host = request.remote_addr
        log.process_log(host, json.loads(body_data.lower()), body_data)

    return {'status': 'success'}


if __name__ == '__main__':
    sql.init()
    rule.init_rule()
    app.run(debug=True, host="0.0.0.0")
