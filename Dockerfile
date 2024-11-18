# Sử dụng Python base image
FROM python:3.9-slim

# Cập nhật các gói cần thiết và cài đặt pip
RUN apt-get update && apt-get install -y curl && \
    curl -sS https://bootstrap.pypa.io/get-pip.py | python3

# Thiết lập thư mục làm việc trong container
WORKDIR /app

# Sao chép toàn bộ mã nguồn vào container
COPY . /app

# Cài đặt các thư viện cần thiết từ requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Chạy file Python chính
CMD ["python3", "likeofhung.py"]
