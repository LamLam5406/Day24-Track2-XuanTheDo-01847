# DPIA-lite (1 trang)

## 1. Dữ liệu gì

<!-- Loại dữ liệu agent này chạm vào: tên, CCCD, SĐT, STK, email... liệt
kê theo từng tool (search_docs / read_customer). -->

Hệ thống Agent xử lý và tương tác với các nhóm dữ liệu cá nhân (PII) và dữ liệu vận hành sau:

- **Dữ liệu phi cấu trúc / Untrusted Content (`corpus/*.md` thông qua tool `search_docs`)**:
  - Nội dung yêu cầu hỗ trợ, phản ánh của khách hàng (ticket text).
  - Có thể chứa PII thô do người dùng nhập hoặc mã độc injection (`customer_id`, email, số điện thoại, STK, CCCD).
  - Phân loại dữ liệu: `internal` / `untrusted`.
- **Dữ liệu có cấu trúc / Private Data Store (`data/customers.json` thông qua tool `read_customer`)**:
  - Mã định danh khách hàng: `customer_id` (ví dụ: `KH-000001`, `KH-000999`).
  - Họ và tên chủ thể dữ liệu (`name`).
  - Căn cước công dân (`cccd` - 12 chữ số).
  - Số điện thoại liên hệ (`phone` - 10 chữ số).
  - Số tài khoản ngân hàng (`bank_account` - 8-16 chữ số).
  - Địa chỉ thư điện tử (`email`).
  - Phân loại dữ liệu: `restricted` (Dữ liệu cá nhân nhạy cảm / tài chính).
- **Dữ liệu Audit & Giám sát (`reports/ledger.jsonl`)**:
  - Dấu vết thực thi tool call, định danh agent (`agent_owner`, `run_id`), hàm băm tham số (`args_hash`), nhãn phân loại, quyết định (`allow`/`deny`), lý do (`reason`), mã băm SHA-256 chuỗi khối (`prev_hash`, `hash`).

## 2. Mục đích gì

<!-- Vì sao agent cần đọc dữ liệu này để trả lời yêu cầu người dùng. -->

- **Mục đích nghiệp vụ chính**:
  - Tìm kiếm, tổng hợp và tóm tắt trạng thái các phiếu hỗ trợ kỹ thuật / khiếu nại khách hàng (`search-tickets`, `summarize-tickets`).
  - Đối soát và xác thực thông tin tài khoản khi có yêu cầu hợp lệ được liên kết trực tiếp qua `related_tickets` (`customer-verification`).
- **Nguyên tắc giảm thiểu dữ liệu (Data Minimization)**:
  - Áp dụng module PII Redaction (`agent/pii.py`) để loại bỏ các trường CCCD, SĐT, STK, Email khỏi context trước khi chuyển tiếp.
  - Áp dụng Trifecta Split (`agent/runner.py`): Không nạp toàn văn dữ liệu nhạy cảm vào context LLM; Run B chỉ tra cứu customer_id từ danh sách ID số học đã được sanitize (typed ticket IDs), không dựa vào free text từ người dùng hoặc tài liệu chưa tin cậy.

## 3. Chảy đi đâu

<!-- Toàn bộ nơi dữ liệu này có thể đi tới: log nội bộ, sink (trong lab),
và — nếu dùng --model claude-... — cả API của model provider. Đây là
chuyển dữ liệu xuyên biên giới theo NĐ 356/2025 nếu provider ở nước
ngoài; ghi rõ có hay không, và agent có egress control nào chặn việc này
khi không cần thiết. -->

- **Luồng nội bộ (Local Processing & Storage)**:
  - Dữ liệu `corpus/` và `data/customers.json` được đọc và xử lý trên bộ nhớ cục bộ của server.
  - Toàn bộ hành vi được ghi log vào Audit Ledger bất biến (`reports/ledger.jsonl`).
- **Luồng ngoại vi / Egress Channel**:
  - **Sink mô phỏng (`localhost:9999`)**: Bị chặn cứng qua Policy Enforcement Point (`agent/policy.py`). Mọi nỗ lực gửi dữ liệu nhạy cảm ra ngoài đều bị từ chối (`decision=deny`).
  - **Môi trường `--mock`**: Xử lý 100% deterministic cục bộ, không phát sinh bất kỳ kết nối mạng hay truyền tải dữ liệu ra bên ngoài.
  - **Môi trường Cloud LLM (`--model` qua Anthropic API / OpenAI / Google AI)**:
    - Nếu kích hoạt `--model`, prompt tóm tắt phiếu hỗ trợ sẽ được gửi tới máy chủ của bên thứ ba (đặt tại nước ngoài).
    - **Tuân thủ Nghị định 356/2025 / NĐ 13/2023**: Đây là hoạt động chuyển dữ liệu cá nhân ra nước ngoài (Cross-Border Data Transfer). Hệ thống bắt buộc phải:
      1. Thực hiện PII Gate (`agent/pii.py:redact`) để che dấu toàn bộ PII trước khi gửi payload tới API provider.
      2. Lập hồ sơ đánh giá tác động chuyển dữ liệu ra nước ngoài và lưu trữ phục vụ thanh tra trong thời hạn quy định (60 ngày).
      3. Thiết lập chính sách Egress Whitelist và cách ly Run A / Run B để ngăn ngừa việc rò rỉ dữ liệu Private Store sang nhà cung cấp mô hình.
