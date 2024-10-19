from flask import Flask, request, jsonify
from main import start_like
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
executor = ThreadPoolExecutor(max_workers=5)

@app.route('/getlike', methods=['GET'])
def get_like():
    uid = request.args.get('uid')

    if uid is None:
        return jsonify({"error": "Bạn chưa cung cấp api"}), 400

    if not uid.isdigit() or not (8 <= len(uid) <= 12):
        return jsonify({"error": "UID không hợp lệ. UID phải là từ 8 đến 12 số."}), 400

    try:
        # Gọi trực tiếp hàm để kiểm tra
        start_like(uid)

        return jsonify({
            "Dev": "HVH VZ",
            "status": "Đã buff like thành công",
            "id": uid,
            "game": "Free Fire"
        }), 200
    except Exception as e:
        print(f"Error: {e}")  # Thêm dòng log lỗi nếu có
        return jsonify({"error": "Đang trục chặc kỹ thuật."}), 500
