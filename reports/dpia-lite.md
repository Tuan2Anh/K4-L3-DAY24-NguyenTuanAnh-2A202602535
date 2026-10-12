# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
- Dữ liệu yêu cầu hỗ trợ khách hàng trong `corpus/*.md`: Phân loại `internal`.
- Dữ liệu hồ sơ khách hàng trong `data/customers.json` (chứa tên, CCCD, SĐT, STK, Email): Phân loại `restricted`.
- Dữ liệu kết quả tóm tắt cho người dùng: Phân loại `internal` (đã qua PII redaction).

2. Mục đích xử lý và principal:
- `support_l1`: Mục đích `summarize-tickets`, `support-reply`. Chỉ được phép đọc tài liệu (`search_docs`), bị từ chối truy cập hồ sơ nhạy cảm (`read_customer`).
- `dpo`: Mục đích `summarize-tickets`, `support-reply`, `privacy-audit`. Được phép đọc tài liệu và hồ sơ khách hàng hợp lệ phục vụ công tác kiểm toán và giải quyết khiếu nại.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
- Run A: Đọc văn bản chưa tin cậy qua `search_docs`, làm sạch PII qua `agent.pii.redact`, chỉ trích xuất danh sách ID ticket qua tên file.
- Ranh giới Run A -> Run B: Chỉ truyền danh sách số nguyên `ticket_ids`, hoàn toàn cô lập free text của kẻ tấn công.
- Run B: Tra cứu khách hàng từ `related_tickets` trong `customers.json`, gọi `read_customer` (sau khi policy kiểm tra).
- Cổng Egress: Yêu cầu gọi `http_post` ra endpoint `http://127.0.0.1:10024/reconcile` bị Policy Enforcement Point chặn hoàn toàn vì mang nhãn `restricted`. Không có dữ liệu nào thoát ra sink.

4. Bằng chứng deny/allow và giới hạn của mock:
- Bằng chứng allow/deny: Ghi nhận đầy đủ trong `reports/ledger.jsonl` (23 entries, dòng cuối cùng từ chối `http_post` cho `dpo` với lý do `Egress is strictly prohibited for restricted data classification`).
- File `reports/attack-after.log` có kích thước 0 byte (so với `reports/attack-before.log` bị lộ 4 bản ghi).
- Giới hạn: Toàn bộ quá trình chạy với cờ `--mock` trên dữ liệu giả lập (synthetic data). Kết quả chứng minh tính đúng đắn của kiến trúc bảo mật trong lab, không thay thế cho hệ thống xác thực và đánh giá an toàn thực tế.
