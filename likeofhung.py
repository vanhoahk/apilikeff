from flask import Flask, request, jsonify
from main import start_like
import asyncio

app = Flask(__name__)

@app.route('/getlike', methods=['GET'])
async def get_like():
    uid = request.args.get('uid')

    if uid is None:
        return jsonify({"error": "Bạn chưa cung cấp api"}), 400

    if not uid.isdigit() or not (8 <= len(uid) <= 12):
        return jsonify({"error": "UID không hợp lệ. UID phải là từ 8 đến 12 số."}), 400

    try:
        # Sử dụng asyncio để chạy hàm bất đồng bộ
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, start_like, uid)
        
        return jsonify({
            "Dev": "HVH VZ",
            "status": "Đã buff like thành công",
            "id": uid,
            "game": "Free Fire"
        }), 200
    except Exception as e:
        return jsonify({"error": "Đang trục chặc kỹ thuật."}), 500
