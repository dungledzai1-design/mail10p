# HƯỚNG DẪN DEPLOY SERVER KEY LÊN RENDER (onrender.com) MIỄN PHÍ

Hệ thống quản lý bản quyền License Key & Điều khiển từ xa cho **Letiendung Mod Pokemon** dành riêng cho Admin Dũng Lê.

---

## 🚀 Cách 1: Deploy qua GitHub lên Render (Khuyên dùng - 2 phút)

1. **Tạo GitHub Repository mới:**
   - Vào [github.com](https://github.com) -> New repository -> Đặt tên `pokemon-key-server` (để Private hoặc Public đều được).
   - Tải toàn bộ các file trong thư mục `pokemon_server` lên repo này:
     - `app.py`
     - `requirements.txt`
     - `Procfile`
     - `render.yaml`

2. **Tạo Web Service trên Render:**
   - Đăng nhập vào [dashboard.render.com](https://dashboard.render.com).
   - Bấm **New +** -> Chọn **Web Service**.
   - Kết nối tới GitHub repo `pokemon-key-server` vừa tạo.
   - Điền cấu hình:
     - **Name:** `letiendung-key-server` (hoặc tên tuỳ chọn)
     - **Runtime:** `Python 3`
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `gunicorn app:app --bind 0.0.0.0:$PORT`
     - **Instance Type:** `Free` (Miễn phí 100%)
   - Mục **Environment Variables** (Biến môi trường):
     - `ADMIN_PASSWORD`: `dungledzvl`
     - `SECRET_KEY`: nhập một chuỗi ngẫu nhiên bất kỳ
   - Bấm **Create Web Service**.

3. **Lấy link Web Server:**
   - Sau 1-2 phút Render build xong, bạn sẽ nhận được đường dẫn dạng:
     `https://letiendung-key-server.onrender.com`
   - Đăng nhập vào link trên bằng mật khẩu: `dungledzvl`.
   - Gắn link web này vào extension để khách hàng kết nối và xác thực Key!

---

## 🔐 Đăng nhập & Sử dụng

- **Mật khẩu quản trị:** `dungledzvl`
- **Các tính năng trên web:**
  1. **Quản lý Key:** Tạo key mới (1 ngày, 7 ngày, 30 ngày, 90 ngày, 1 năm, vĩnh viễn), gia hạn key (+30 ngày), khóa/mở khóa key, reset máy (HWID), xóa key.
  2. **Theo dõi Realtime 24/7:** Xem danh sách người chơi đang bật tool trực tiếp, tên tài khoản Pokémon đang chơi, tổng số giờ cày, thiết bị (Kiwi Browser Android hay PC), địa chỉ IP.
  3. **Điều khiển từ xa (Remote Control):**
     - Bật chế độ bảo trì hệ thống (hiển thị thông báo bảo trì trên tool).
     - Bật/tắt từ xa các chức năng: God Mode (Bất tử), One-Hit, Mở khoá tất cả Pokémon, Auto Farm.
