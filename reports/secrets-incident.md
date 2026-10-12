# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1
- Commit chứa token giả: `1bdd849922156c868a5ee9293d68f5b72e242d2c` (commit `1bdd849`)
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt` (dòng 1)
  - Rule: `lab24-synthetic-token`
  - Kết quả: Quét lịch sử với `gitleaks git --config .gitleaks.toml --redact .` phát hiện 1 finding (`leaks found: 1`, exit code 1) đúng token giả synthetic được cài sẵn trong lịch sử.
- Kết quả quét file hiện tại:
  - Quét với `gitleaks dir --config .gitleaks.toml --redact .` trả về `no leaks found` (exit code 0), cây thư mục hiện tại hoàn toàn sạch.
- Nếu đây là credential thật, cần xử lý thế nào:
  - Phải lập tức thu hồi (revoke) và rotate credential tại hệ thống/nhà cung cấp dịch vụ cấp phát khóa, vô hiệu hóa ngay token cũ.
  - Kiểm tra audit log của dịch vụ để rà soát các hành vi truy cập bất thường từ thời điểm commit bị lộ.
  - Báo cáo sự cố an ninh thông tin và xử lý các bản sao clone của repo.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xóa file ở commit mới (HEAD) chỉ loại bỏ file khỏi working tree hiện tại; toàn bộ nội dung secret vẫn nằm nguyên vẹn trong lịch sử Git commit tree (Git object database) và bất kỳ ai có quyền truy cập repo đều xem được qua `git log` hoặc `git show`.
  - Pin dependency và pre-commit hook chỉ giúp bảo vệ tính toàn vẹn chuỗi cung ứng và ngăn ngừa secret mới bị push lên, không có khả năng vô hiệu hóa một credential đã phát tán ra ngoài. Do đó, bắt buộc phải rotate / thu hồi tại dịch vụ cấp token.
