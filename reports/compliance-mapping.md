# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Cơ chế cascade deletion đối với dữ liệu cá nhân khi nhận được yêu cầu từ chủ thể dữ liệu (chưa implement, xem stretch #4) | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory và đánh giá tác động truyền dữ liệu cho LLM API call | [`reports/dpia-lite.md`](file:///d:/AITHUCCHIEN/PHASE2/Day24-Track2-XuanTheDo-01847/reports/dpia-lite.md#L1-L40) §2-§3 |
| ASI03 — privilege abuse | Phân quyền theo agent identity (`agent_owner`), kiểm soát delegation depth và ghi nhận audit log tamper-evident | [`agent/policy.py`](file:///d:/AITHUCCHIEN/PHASE2/Day24-Track2-XuanTheDo-01847/agent/policy.py#L13-L49), [`agent/ledger.py`](file:///d:/AITHUCCHIEN/PHASE2/Day24-Track2-XuanTheDo-01847/agent/ledger.py#L13-L65) |
| ASI01 — goal hijack | Kiểm soát kiến trúc Trifecta Split (cách ly untrusted context Run A khỏi private data Run B và chặn egress) | [`agent/runner.py`](file:///d:/AITHUCCHIEN/PHASE2/Day24-Track2-XuanTheDo-01847/agent/runner.py#L26-L107), [`reports/attack-after.log`](file:///d:/AITHUCCHIEN/PHASE2/Day24-Track2-XuanTheDo-01847/reports/attack-after.log#L1-L3) |
| ISO 42001 Clause 5-6 | Quản trị rủi ro AI & Policy-as-Code có kiểm soát, phiên bản hóa và kiểm thử tự động | [`agent/policy.py`](file:///d:/AITHUCCHIEN/PHASE2/Day24-Track2-XuanTheDo-01847/agent/policy.py#L30-L50), [`tests/test_policy.py`](file:///d:/AITHUCCHIEN/PHASE2/Day24-Track2-XuanTheDo-01847/tests/test_policy.py#L1-L42) |
