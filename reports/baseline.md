# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
Chưa có. Trong hàm `_naive_loop()` tại file `agent/loop.py` (dòng 27–52), agent hoàn toàn không khởi tạo hoặc quản lý `principal_id`, `agent_owner`, `run_id` hay bất kỳ cơ chế xác định danh tính hoặc ngữ cảnh ủy quyền nào cho mỗi lượt chạy.

2. Ai cho phép `http_post`? Dẫn file/hàm:
Không có ai hoăc không có cơ chế chính sách nào kiểm soát. Trong hàm `_naive_loop()` tại file `agent/loop.py` (dòng 44), agent gọi trực tiếp `tools.http_post(injected.target_url, ...)` ngay khi trích xuất được chỉ thị injected, hoàn toàn bỏ qua điểm thực thi chính sách và kiểm tra egress allowlist.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
Bằng chứng được lưu tại file `reports/sink.log`, do hàm `do_POST()` của lớp `Handler` (được định nghĩa trong hàm `make_handler()` tại file `sink/sink.py`, dòng 42–47) ghi lại toàn bộ `path` và `body` của request HTTP POST gửi tới localhost:10024.
hoăc