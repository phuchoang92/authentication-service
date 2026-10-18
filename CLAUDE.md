# Luật thiết kế code

`AGENTS.md` là authority về luật riêng của dự án (Keycloak, persistence layout, naming adapter).
File này chỉ nói **cách chia class và chia kiểu dữ liệu**. Mâu thuẫn ⇒ `AGENTS.md` thắng.

Mục tiêu: người mới đọc một hàm là biết nó làm gì; muốn biết sâu thì mở collaborator.
Mỗi luật dưới đây **chạy được một lệnh để kiểm**. Luật không kiểm được là lời khuyên, không phải luật.
Lệnh kiểm chạy từ `src/main/java/com/vpbank/dcp`.

## 0. Bốn câu hỏi chặn trước khi tạo class mới

1. **Logic dài hơn ceremony không?** `logic = LOC − (package + import + blank + field + ctor)`.
   Ceremony ≈ 20 dòng. **`logic < 20` ⇒ không tạo class** — nó là một method của class đã có.
2. **Đã thấy pattern này 3 lần chưa?** Hai lần là trùng hợp, chưa phải pattern.
3. **Là *năng lực* hay chỉ là *danh từ*?** `challenge` thuộc về `operation`; `claim` thuộc về
   `request`. **Danh từ ≠ collaborator.**
4. **Thuộc đúng một vai?** adapter / use case / năng lực. Trộn hai vai là sai.

## 1. Không tạo service chỉ để chuyển tiếp

Dấu hiệu, chắc chắn giảm dần:
- chỉ dùng port của **chính package mình**
- thân hàm là một lệnh gọi port rồi `map`/`instanceof` sang kiểu khác
- không có nhánh quyết định nào

**Kiểm:**
```bash
for f in $(find core/application -name '*Service.java'); do
  echo "$(basename $f .java) [$(dirname $f | sed 's|.*/||')] <- \
$(grep -oE 'port\.out\.[a-z]+' $f | sed 's/.*\.//' | sort -u | tr '\n' ' ')"
done
```
`[x] <- x` (chỉ port trùng tên package) ⇒ **inline vào caller**.

## 2. Năng lực A không được giữ năng lực B

Vẫn lệnh trên: `[mfa] <- ... session ...` nghĩa là `mfa` đang điều phối thay cho use case.
Chỉ **use case** được ghép nhiều năng lực; **năng lực** chỉ biết port của chính nó.
Ngoại lệ phải viết lý do ngay trên class, không im lặng.

## 3. Một class cho một NĂNG LỰC, không phải một endpoint

6 class (1/endpoint) ≈ 132 dòng ceremony / 25 dòng logic (**84%**).
1 class năng lực ≈ 22 / 25 (**47%**).

**Kiểm:** `ls core/application/<pkg>/*.java | wc -l` ≤ số **năng lực** của package đó.
**Chỉ tách khi bị ép:** >5 collaborator, >200 dòng, hoặc xuất hiện lý do thay đổi thứ hai
**đã quan sát được** — không phải dự đoán.

## 4. Module sâu, không module nông

Deep = ít method, giấu nhiều. Shallow = nhiều method, giấu ít.
**Kiểm:** `LOC thân / số public method`. **< 3 ⇒ nông**, xem lại.
Một record một field tách file riêng chỉ xứng đáng khi nó **chặn được lỗi biên dịch** mà kiểu
gốc không chặn (ví dụ: hai `UUID` liền nhau đổi chỗ được).

## 5. Đừng implement ý đầu tiên

Sinh **2–3 phương án khác nhau về bản chất**, phác chỉ các method quan trọng, so sánh từ
**phía người gọi**, rồi mới chọn. Viết 2 dòng lý do chọn.

## 6. Kết quả và lỗi — khai một lần, map một lần

- Outcome **mang dữ liệu + dẫn tới hành vi khác nhau** ⇒ sealed + `switch` exhaustive,
  **không `default`** (thêm variant mới phải gây lỗi biên dịch).
- Outcome **kết thúc luồng, không mang dữ liệu** ⇒ **một** kiểu terminal dùng chung cả luồng.
- **Cấm** khai lại cùng cặp `Rejected`/`Unavailable` ở mỗi tầng: mỗi lần dịch là một lần mất
  thông tin, và chỗ mất không báo lỗi.
- `default` **chỉ** cho giá trị từ hệ ngoài (`String` trả về từ API/DB) — ở đó nó bắt buộc.
- Mỗi variant phải có **người tạo** và **người đọc**. Thiếu một trong hai ⇒ nhánh chết.
- Kết cục mong đợi là **giá trị**, không phải exception (`RULES:1658`).

**Kiểm:**
```bash
grep -rhoE 'record [A-Z][A-Za-z]*\(\s*\)' core/ | sort | uniq -c | sort -rn
grep -rc instanceof core/application/*/*.java | grep -v ':0' | sort -t: -k2 -rn
grep -rn 'new <Type>\.<Variant>(' core/ infrastructure/     # variant nào không ai tạo?
```
Một tên variant rỗng xuất hiện >1 lần trong cùng luồng ⇒ **đang dịch vô ích**.
Một class >5 `instanceof` ⇒ nó là bộ dịch, không phải logic.

## 7. Tên

- Động từ đúng việc: `issue` ≠ `store`, `decide` ≠ `verify`.
- Chữ ký đoán được từ tên: `requireX` **ném** · `findX` trả `Optional` · `decideX` trả sealed.
- Cấm `Manager`, `Utils`, `Helper`, `Processor`, `Handler`, `*Impl`.
- Tên chứa `token`/`key` **không** tự động là transport. Xét **nơi khai báo kiểu**, không xét tên:
  `PreparedPendingToken` là domain của hệ này, `HttpHeaders` thì không.

**Kiểm:** đọc tên method rồi đoán chữ ký. Đoán sai ⇒ đổi tên, đừng thêm javadoc.

## 8. Trùng lặp rẻ hơn abstraction sai

Gỡ một abstraction sai **đắt hơn** gỡ trùng lặp. Chưa chắc hai chỗ là **cùng một thứ** hay chỉ
**trông giống nhau** ⇒ để nguyên. Chuỗi ký tự giống nhau không có nghĩa là cùng khái niệm
(`RULES:761`).

## 9. Checklist trước khi nộp

- [ ] Mỗi class mới có logic > 20 dòng
- [ ] Không service nào chỉ dùng port của chính package mình
- [ ] Không năng lực nào giữ collaborator của năng lực khác
- [ ] Mỗi class ≤ 5 collaborator, ≤ 200 dòng
- [ ] Không `switch` nào trên **sealed** có `default`
- [ ] Mỗi variant có cả người tạo lẫn người đọc
- [ ] Đoán được chữ ký của mọi public method từ tên nó
- [ ] Thay đổi có **tiêu chí thành công đo được**, không phải mô tả các bước

## Nguồn

Ousterhout *A Philosophy of Software Design* (deep modules; "never implement your first idea") ·
Sandi Metz [The Wrong Abstraction](https://sandimetz.com/blog/2016/1/20/the-wrong-abstraction) ·
[Rule of Three](https://understandlegacycode.com/blog/refactoring-rule-of-three/) ·
Fowler [Anemic Domain Model](https://www.martinfowler.com/bliki/AnemicDomainModel.html) ·
[Google Java Style](https://google.github.io/styleguide/javaguide.html) ·
[How to write a good CLAUDE.md](https://www.builder.io/blog/claude-md-guide) —
*"each line should change a decision or name a check"*, giữ file dưới ~200 dòng.
