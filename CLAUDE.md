# Luật code — Authentication Service

**Tầng và package:** [`ARCHITECTURE.md`](ARCHITECTURE.md) là nguồn duy nhất (2026-10-24).

**Thứ tự ưu tiên:** hợp đồng DD target (API, bảo mật, dữ liệu) > `AGENTS.md` > file này >
tài liệu luật chung `code-design-rules-and-patterns.md`. Ba override của file này (§2, §3, §5)
đã được người dùng duyệt ngày 2026-10-18 và được ghi trong `AGENTS.md` (§ Code structure).
Phần nào file này không nói thì tài liệu chung vẫn áp dụng, nhất là bảo mật, persistence và
Redis key RK01–RK12.

**Mục tiêu đo được:** người mới trace được một endpoint. Chỉ số chính là số kiểu phải mở khi
đi từ controller tới SQL/HTTP/Valkey, tính cả implementation của interface:

```bash
python3 tools/code-metrics.py          # chạy từ thư mục authentication-service
```

Mốc 2026-10-18: `PasswordLoginController` 196 kiểu, `TrustedDeviceController` 179 kiểu;
341 file, trong đó 131 file ≤ 15 dòng. **Một thay đổi không thêm hành vi thì không được làm các
số này tăng.** Luật không kiểm được bằng lệnh là lời khuyên, không phải luật.

## 1. Giữ nguyên — phần đã đúng

- Core chỉ dùng JDK. Spring, HTTP, SQL, Valkey, JOSE/Nimbus nằm ở `infrastructure`.
  Kiểm: ArchUnit `CORE_DOES_NOT_IMPORT_FRAMEWORK`, `CORE_DOES_NOT_IMPORT_INFRASTRUCTURE`.
- Adapter dịch định dạng và lỗi của bên ngoài thành kiểu của core. Core không catch exception
  của vendor.
- Kết cục mong đợi (từ chối, đang chờ MFA, hết hạn, xung đột) là **giá trị**, không phải exception.
- Persistence: adapter giữ transaction, repository chỉ chạy SQL (luật trong `AGENTS.md`).

## 2. Tầng, package và hướng phụ thuộc

Chuyển sang [`ARCHITECTURE.md`](ARCHITECTURE.md) (2026-10-24): tầng nào giữ gì, mỗi năng lực
`core/<năng lực>/` gồm những loại kiểu nào, bảng hướng phụ thuộc giữa các năng lực, thứ tự các
lát chuyển và checklist mỗi lát. File này không lặp lại các luật đó.

## 3. Interface chỉ ở biên thật (override H04)

Xem [`ARCHITECTURE.md` §2](ARCHITECTURE.md#2-inside-one-core-capability). Không có interface
`*UseCase` phía vào; controller gọi thẳng class service.

**Kiểm:** `python3 tools/code-metrics.py ports` — danh sách phải rỗng.

## 4. Một khái niệm — một kiểu

- Không tạo `Candidate`/`Prepared`/`Stored`/`Snapshot`/`View` song song cho cùng một khái niệm,
  trừ khi mỗi kiểu có bất biến khác mà người gọi dựa vào. Ví dụ hợp lệ: `Prepared…` mang token
  plaintext để giao cho App, `Stored…` thì không bao giờ. Viết lý do đó ngay trên kiểu.
- Record trong core ≤ 6 thành phần. Hơn thế thì gom theo nghĩa: chủ sở hữu, khoá, thời hạn.
- Không để hai `boolean` liền nhau. Dùng enum hoặc kiểu có tên (`DeviceStanding`), vì
  `new X(true, false, true)` không đọc được.
- DTO web, DTO HTTP của đối tác, projection và dòng DB được phép rộng: chúng phản chiếu hình
  dạng bên ngoài.

**Kiểm:** `python3 tools/code-metrics.py records`.

## 5. Exception (override EH02/EH05)

- Tạo class exception riêng **chỉ khi** có `catch` hoặc `@ExceptionHandler` phân biệt nó.
  Ví dụ cần giữ: `MfaUnavailableException` (application đổi nó thành `Unavailable`).
- Sai cấu hình lúc khởi động: `IllegalStateException` nêu **tên setting**, không nêu giá trị.
- Bất biến bị vi phạm do lập trình sai: `IllegalArgumentException`/`IllegalStateException`.
- Vẫn giữ: không đưa message exception ra response; giữ `cause`; không nuốt lỗi để tiếp tục.

**Kiểm:** `python3 tools/code-metrics.py exceptions` — mỗi dòng là một class không ai phân
biệt, ứng viên để gộp.

## 6. Không tạo class chỉ để chuyển tiếp

Trước khi tạo class mới, trả lời đủ bốn câu:

1. **Logic dài hơn ceremony không?** `logic = LOC − (package + import + blank + field + ctor)`.
   `logic < 20` ⇒ không tạo class, viết thành method của class đã có.
2. **Đã thấy pattern này 3 lần chưa?** Hai lần là trùng hợp.
3. **Là năng lực hay chỉ là danh từ?** `challenge` thuộc `operation`; danh từ không phải collaborator.
4. **Thuộc đúng một vai?** adapter / service / policy. Trộn hai vai là sai.

Dấu hiệu service chuyển tiếp: thân hàm là một lệnh gọi rồi `map`/`switch` sang kiểu khác, không
có nhánh quyết định nào ⇒ inline vào caller.
Tách class chỉ khi bị ép: > 5 collaborator, > 200 dòng, hoặc đã **quan sát được** lý do thay
đổi thứ hai.

## 7. Kết quả và lỗi — khai một lần, map một lần

- Outcome mang dữ liệu và dẫn tới hành vi khác nhau ⇒ sealed + `switch` exhaustive, **không
  `default`**.
- Cấm khai lại cùng cặp `Rejected`/`Unavailable` ở mỗi tầng; mỗi lần dịch là một lần mất thông tin.
- `default` chỉ dùng cho giá trị từ hệ ngoài (`String` từ API/DB).
- Mỗi variant phải có người tạo và người đọc; thiếu một trong hai là nhánh chết.

**Kiểm:**
```bash
grep -rhoE 'record [A-Z][A-Za-z]*\(\s*\)' src/main/java | sort | uniq -c | sort -rn
```
Mốc 2026-10-18: `Rejected()` 11 lần, `Unavailable()` 6 lần. Con số này phải giảm, không tăng.

## 8. Code chết

Class không được wire và không có caller trong `src/main` thì xoá, cùng test của nó. Test xanh
không phải lý do để giữ.

**Kiểm:** `python3 tools/code-metrics.py dead`.

## 9. Tên

- Động từ đúng việc: `issue` ≠ `store`, `decide` ≠ `verify`.
- Chữ ký đoán được từ tên: `requireX` ném · `findX` trả `Optional` · `decideX` trả sealed.
- Không dùng `Manager`, `Utils`, `Helper`, `Processor`, `Handler`, `*Impl`, `Route`.
- Dùng từ người mới hiểu được, kể cả người không giỏi tiếng Anh.

**Kiểm:** đọc tên method rồi đoán chữ ký. Đoán sai ⇒ đổi tên, đừng thêm javadoc.

## 10. Trùng lặp rẻ hơn abstraction sai

Gỡ một abstraction sai đắt hơn gỡ trùng lặp. Chưa chắc hai chỗ là **cùng một thứ** hay chỉ
**trông giống nhau** thì để nguyên.

## 11. Checklist trước khi nộp

- [ ] `python3 tools/code-metrics.py` không tăng số kiểu trace nếu không thêm hành vi
- [ ] Không interface mới ngoài biên thật (§3)
- [ ] Code mới nằm trong `core/<năng lực>/` (§2)
- [ ] Không exception mới mà không ai catch (§5)
- [ ] Record mới trong core ≤ 6 thành phần, không hai boolean liền nhau (§4)
- [ ] Mỗi class mới có logic ≥ 20 dòng, ≤ 5 collaborator, ≤ 200 dòng (§6)
- [ ] `switch` trên sealed không có `default`; mỗi variant có người tạo và người đọc (§7)
- [ ] `mvn -o clean verify` xanh

## Nguồn

Ousterhout *A Philosophy of Software Design* (deep modules) ·
Sandi Metz [The Wrong Abstraction](https://sandimetz.com/blog/2016/1/20/the-wrong-abstraction) ·
[Rule of Three](https://understandlegacycode.com/blog/refactoring-rule-of-three/) ·
Cockburn [Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/) — ý gốc
là tách ứng dụng khỏi thứ bên ngoài; bố cục package và interface phía vào ở đây là lựa chọn của
dự án (§2, §3).
