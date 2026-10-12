# Compliance mapping — điền trong checkpoint 5

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 | PII detection & redaction, kiểm soát quyền truy cập dữ liệu nhạy cảm (OBO) | [agent/pii.py:10-55](agent/pii.py), [agent/policy.py:38-60](agent/policy.py) | Dữ liệu tổng hợp (synthetic), quy tắc regex nhận diện theo mẫu cố định |
| NĐ 356/2025/NĐ-CP | Ghi nhận nhật ký kiểm toán không thể giả mạo (Audit Ledger Hash Chain) | [agent/ledger.py:16-65](agent/ledger.py), [reports/ledger.jsonl](reports/ledger.jsonl) | Hash chain lưu trên một file cục bộ, chưa gắn mốc thời gian (timestamp authority) bên ngoài |
| Luật AI 134/2025/QH15 | Kiểm soát luồng thực thi tác vụ AI, ngăn chặn Prompt Injection và vượt quyền | [agent/runner.py:53-118](agent/runner.py) | Môi trường thử nghiệm dùng Mock LLM deterministic, chính sách phân quyền cục bộ |
| OWASP ASI01, ASI03, ASI04 | Tách biệt ngữ cảnh (Trifecta Split), ràng buộc quyền theo vai trò (OBO), chặn egress dữ liệu Restricted | [agent/runner.py:53-70](agent/runner.py), [agent/policy.py:27-29](agent/policy.py) | Lab chỉ mô phỏng egress tới localhost:10024, chưa áp dụng proxy gateway mạng thực |

Chỉ ghi điều khoản cụ thể khi đã đối chiếu văn bản gốc. Mô phỏng kỹ thuật không tự chứng minh tuân thủ pháp luật.
