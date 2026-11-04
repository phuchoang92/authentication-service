# Trusted device — contract ML-DSA-65 và cURL

**Trạng thái: đề xuất để review, chưa phải API đang chạy.** Tài liệu mô tả hai nhánh: tự enrollment để trở thành primary (`/init → /verify → /confirm`) và duyệt bằng thiết bị cũ. Ở nhánh duyệt, thiết bị mới gọi `/request`, thiết bị cũ hoàn tất MFA và gọi `/confirm` để lấy `authorizationCode`, thiết bị mới gọi `/claim`. Không có bước `/authorize` trong contract này. Source tại thời điểm soạn vẫn có route `pending/{enrollmentId}/authorize` và claim nhận `authorizationToken`; các mẫu dưới đây dành cho contract mục tiêu, không chạy nguyên trạng trên source đó. `/confirm` ở đây là `pending/{enrollmentId}/confirm`, phân biệt với `/trusted-device/confirm` của nhánh tự enrollment.

## Quy ước chung

- Các URL ví dụ là **BFF → Auth** qua HTTPS. Header `Authorization: Bearer …` chứa assertion do BFF ký sau khi kiểm tra phiên App; không truyền token App trực tiếp vào Auth ở ranh giới này. Cần assertion mới cho mỗi lần gọi, với danh tính, channel, installation và trạng thái phiên chính xác. Xem [contract BFF hiện tại](plans/slice-11-bff-admitted-trust-flows.md).
- Thiết bị mới dùng phiên `NEED_TRUSTED_DEVICE`. Thiết bị cũ dùng phiên `ACTIVE` và phải là primary còn hiệu lực của cùng khách hàng/kênh. Auth lấy danh tính và installation từ admission, không nhận chúng từ body.
- ID trên wire là chuỗi opaque; timestamp UTC RFC 3339. JSON thành công có `{ "success": true, "data": … }`; lỗi có `{ "success": false, "error": { "code": …, "message": …, "details": [] } }`. Correlation nằm ở response header `X-Correlation-Id`. Response chứa code dùng `Cache-Control: no-store`.
- `Kdev` là khóa **ký** ML-DSA-65. App giữ private key; Auth lưu public key gắn với enrollment và giữ lại trên binding khi enrollment hoàn tất. Khóa ký này tách biệt với bất kỳ khóa mã hóa nào mà Smart OTP sử dụng.
- Public JWK ML-DSA-65 dùng `kty=AKP`, `alg=ML-DSA-65`, `pub` là 1.952 byte raw public key mã hóa Base64URL không padding; không gửi `priv`. Thumbprint tính theo [RFC 9964 §6](https://datatracker.ietf.org/doc/html/rfc9964#section-6). Proof trên wire là **chữ ký raw**, không phải JWS, nhất quán với [profile device proof](plans/slice-13-device-proof.md). Thuật toán ký theo [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), context rỗng.
- Tất cả cURL dùng dữ liệu fixture. Các biến `BFF_*` là assertion riêng cho từng request; `AUTH_BASE` là URL Auth của môi trường test. cURL không sinh chữ ký hoặc assertion.

## Nhánh duyệt bằng thiết bị cũ

### 1. Thiết bị mới — POST /api/v1/trusted-device/request

**Body:** `devicePublicJwk` (object, bắt buộc) và `platform` (`ANDROID` hoặc `IOS`, bắt buộc). Auth kiểm tra key type, thuật toán, độ dài, encoding và loại bỏ yêu cầu chứa private key. Auth lưu public key cùng thumbprint, chủ sở hữu, kênh, installation và hạn của enrollment. Public key này là **ứng viên**, chưa được trust và chưa có proof-of-possession.

Nếu có enrollment mở cho cùng installation, request lại với cùng key và platform trả enrollment đó; khác key hoặc platform trả conflict. Muốn thay key phải bắt đầu enrollment mới theo chính sách hết hạn/hủy; không cập nhật key giữa chừng. Enrollment thuộc installation đã được BFF xác nhận; restricted session mới của cùng installation có thể tiếp tục, theo [slice 11](plans/slice-11-bff-admitted-trust-flows.md#turns).

```bash
# kdev-public.jwk.json chỉ chứa public JWK của thiết bị mới.
jq -n --slurpfile kdev kdev-public.jwk.json \
  '{devicePublicJwk: $kdev[0], platform: "IOS"}' > request.json

curl -sS -X POST "$AUTH_BASE/api/v1/trusted-device/request" \
  -H "Authorization: Bearer $BFF_NEW_REQUEST" \
  -H 'Content-Type: application/json' \
  --data-binary @request.json
```

**200**

```json
{
  "success": true,
  "data": {
    "status": "WAITING_APPROVAL",
    "enrollmentId": "enr_example",
    "expiresAt": "2026-11-04T03:00:00Z"
  }
}
```

`expiresAt` là hạn enrollment, không phải hạn code. Request lại trả trạng thái thực của enrollment mở, không phát code mới.

### 2. Thiết bị cũ — chọn yêu cầu và hoàn tất MFA

Thiết bị cũ lấy danh sách pending rồi bắt đầu MFA cho đúng enrollment. Đây là các thao tác hỗ trợ đã có trong luồng duyệt; bước cấp code vẫn chỉ diễn ra ở `/confirm`.

```bash
curl -sS "$AUTH_BASE/api/v1/trusted-device/pending" \
  -H "Authorization: Bearer $BFF_OLD_PENDING"

curl -sS -X POST "$AUTH_BASE/api/v1/trusted-device/pending/$ENROLLMENT_ID/approve" \
  -H "Authorization: Bearer $BFF_OLD_APPROVE"
```

`GET /pending` trả 200 với danh sách trong `data`: `enrollmentId`, ID thiết bị đã che, `platform`, `status`, `expiresAt`. `POST /approve` không có body; trả 200 với `status=MFA_REQUIRED`, `mfaTransactionId`, `expiresAt`. App hoàn tất MFA với nhà cung cấp theo flow hiện có. Auth xác minh kết quả MFA từ nguồn tin cậy, ràng buộc với enrollment, người duyệt và mục đích phê duyệt; không nhận cờ `mfaPassed` từ App.

### 3. Thiết bị cũ — POST /api/v1/trusted-device/pending/{enrollmentId}/confirm

**Body:** không có. Auth kiểm tra thiết bị duyệt vẫn là primary, enrollment đúng chủ sở hữu/kênh, trạng thái cho phép và MFA đã hoàn tất. Auth sinh code ngẫu nhiên **32 byte** (Base64URL không padding), lưu SHA-256 của code và hạn dùng, liên kết với đúng enrollment, installation, thumbprint Kdev đã khóa và người duyệt. Chuyển sang `WAITING_AUTHORIZATION`; chưa trust thiết bị mới.

Hạn code lấy theo cấu hình, giới hạn bởi hạn enrollment. Confirm lặp không cấp code thứ hai hoặc kéo dài hạn. Nếu response chứa code bị mất, trả conflict cho lần confirm lặp; không thể đọc lại code từ digest. App xử lý bằng luồng yêu cầu mới khi enrollment cũ đã đóng theo chính sách.

```bash
curl -sS -X POST "$AUTH_BASE/api/v1/trusted-device/pending/$ENROLLMENT_ID/confirm" \
  -H "Authorization: Bearer $BFF_OLD_CONFIRM"
```

**200**

```json
{
  "success": true,
  "data": {
    "status": "WAITING_AUTHORIZATION",
    "enrollmentId": "enr_example",
    "authorizationCode": "<base64url-code>",
    "expiresAt": "2026-11-03T03:03:00Z"
  }
}
```

Ở response này `expiresAt` là hạn **code**. Thiết bị cũ hiển thị QR với `enrollmentId` và `authorizationCode`. Không để code vào URL, log hoặc analytics. Code không phải session token và không đủ để claim nếu thiếu Kdev.

### 4. Thiết bị mới — POST /api/v1/trusted-device/claim

| Field | Kiểu | Ý nghĩa |
|---|---|---|
| `enrollmentId` | string | ID nhận từ request/QR, phải khớp enrollment của installation được BFF xác nhận |
| `authorizationCode` | string | Code nguyên văn quét từ QR, đúng encoding và còn hạn |
| `deviceProof` | string | Chữ ký ML-DSA-65 raw, 3.309 byte trước khi mã hóa Base64URL không padding |

**Bytes cần ký — V1.** App ký đúng chuỗi UTF-8 `DCP-TRUSTED-DEVICE-CLAIM-V1:<authorizationCode>`, trong đó dấu hai chấm thuộc tiền tố cố định và `<authorizationCode>` được thay bằng code nguyên văn từ QR. Không thêm khoảng trắng, newline hay tiền tố độ dài; không giải mã Base64URL hoặc hash code trước khi ký.

Ví dụ minh họa (code rút ngắn):

```text
DCP-TRUSTED-DEVICE-CLAIM-V1:XYZ12
```

Auth dựng lại chuỗi từ code trong request và xác minh chữ ký bằng public key đã khóa ở enrollment. `enrollmentId` vẫn nằm trong JSON. Auth kiểm tra digest của code **thuộc đúng enrollment đó** và installation đã được BFF xác nhận. SHA-256 chỉ dùng để lưu và đối chiếu code ở server; code vẫn dùng một lần và hết hạn theo thời gian server.

Auth kiểm tra ownership, trạng thái và code digest, rồi kiểm tra proof **trước khi tiêu thụ code**. Tại điểm commit trust, dùng điều kiện cập nhật nguyên tử để recheck trạng thái, hạn, code chưa dùng và binding; hai claim đồng thời chỉ một claim thắng. Đánh dấu code đã dùng và hoàn tất device binding trong cùng transaction dữ liệu trust. Sau khi commit, trả `TRUSTED` để xác nhận trạng thái thiết bị. Claim không cấp token mới, không nâng cấp restricted session thành ACTIVE và không gia hạn phiên. Để có phiên ACTIVE, App đăng nhập lại theo contract login hiện hành và dùng Kdev để tạo proof mới.

```bash
# CLAIM_PROOF được App/test signer tạo từ tiền tố V1 và code nguyên văn.
# Không dùng code hoặc proof thật trong shell history hay dữ liệu test được commit.
jq -n --arg id "$ENROLLMENT_ID" \
  --arg code "$AUTHORIZATION_CODE" \
  --arg proof "$CLAIM_PROOF" \
  '{enrollmentId: $id, authorizationCode: $code, deviceProof: $proof}' > claim.json

curl -sS -X POST "$AUTH_BASE/api/v1/trusted-device/claim" \
  -H "Authorization: Bearer $BFF_NEW_CLAIM" \
  -H 'Content-Type: application/json' \
  --data-binary @claim.json
```

**200**

```json
{
  "success": true,
  "data": {
    "status": "TRUSTED",
    "enrollmentId": "enr_example"
  }
}
```

Thiết bị mới có thể poll `GET /api/v1/trusted-device/status` với assertion riêng `BFF_NEW_STATUS`; response báo trạng thái và enrollment, **không trả code**:

```bash
curl -sS "$AUTH_BASE/api/v1/trusted-device/status" \
  -H "Authorization: Bearer $BFF_NEW_STATUS"
```

## Lỗi và các ca cần kiểm chứng

Các mã dưới đây là mapping đề xuất cho contract mục tiêu; giữ mapping chi tiết của MFA và rate limit khi hoàn thiện API spec.

| HTTP | Code | Tình huống |
|---|---|---|
| 400 | `REQUEST_REJECTED` | JSON/key/proof sai định dạng hoặc thuật toán không hỗ trợ |
| 401 | `WRONG_AUTHORIZATION` | Code hoặc chữ ký không hợp lệ; trả lỗi chung, áp dụng giới hạn lần thử cho enrollment hợp lệ |
| 401 | `AUTHORIZATION_EXPIRED` | Code hết hạn trong enrollment của chính caller |
| 403 | `NOT_PRIMARY_DEVICE` | Caller thiết bị cũ không có quyền duyệt |
| 409 | `STATE_CONFLICT` | Sai trạng thái, khác binding, yêu cầu đổi key giữa chừng, confirm lặp hoặc code đã dùng |
| 409 | `MFA_NOT_PASSED` | MFA chưa hoàn tất |
| 503 | Theo error catalogue hiện hành | Lỗi dependency khi xử lý claim |

Cần có vector ký/verify chung giữa App và Auth cho cả bytes đầu vào và signature verification. Kiểm tra claim hợp lệ; sai private key; đổi code sau khi ký; dùng code với enrollmentId khác; claim từ installation khác; confirm chưa qua MFA; code hết hạn và hai claim đồng thời. Đo giới hạn body qua App/BFF/gateway: riêng proof ML-DSA-65 đã là 4.412 ký tự Base64URL, nên đặt trong body như mẫu.

Sau claim, public Kdev gắn với binding là khóa để xác minh **proof mới** ở lần login sau; không tái sử dụng chữ ký hoặc code của claim. Tài liệu này không đổi contract login, hay mức assurance của khóa.


## Nhánh primary — thiết bị mới tự xác minh

Cả ba API do **cùng thiết bị mới** gọi qua BFF, với phiên `NEED_TRUSTED_DEVICE`. Auth ràng buộc enrollment với khách hàng, kênh, installation, phiên và public key Kdev đã nhận ở `/init`. Mỗi request dùng assertion BFF riêng. Nhánh này không dùng QR hay `authorizationCode`.

Đây là contract mục tiêu: [luồng primary cũ](plans/slice-5-enrollment.md) dùng challenge bọc JWE và cấp token ở confirm. Contract dưới đây trả challenge trực tiếp qua HTTPS, dùng chữ ký ML-DSA-65 để chứng minh giữ Kdev và chỉ hoàn tất trust ở confirm. Không cần cặp khóa mã hóa riêng để thực hiện proof này; nếu Smart OTP cần Ksrv thì áp dụng contract riêng của Smart OTP.

### 1. POST /api/v1/trusted-device/init

| Field | Kiểu | Ý nghĩa |
|---|---|---|
| `devicePublicJwk` | object, bắt buộc | Public JWK ML-DSA-65 của thiết bị mới; App giữ private key |
| `platform` | string, bắt buộc | `ANDROID` hoặc `IOS` |

Auth kiểm tra public JWK theo quy ước chung, tạo enrollment và cố định khóa ứng viên trong enrollment đó. Auth sinh challenge ngẫu nhiên 32 byte, mã hóa Base64URL không padding. Challenge có hạn, dùng một lần và được trả nguyên văn trong JSON qua HTTPS với `Cache-Control: no-store`. Trạng thái `KEY_EXCHANGE` giữ tên hiện tại để biểu thị đang chờ proof; ở contract này không có trao đổi khóa bí mật. Init lặp với cùng phiên và cùng khóa có thể trả lại enrollment và challenge chưa dùng còn hạn; không gia hạn, thay khóa hoặc phát lại challenge đã dùng.

```bash
jq -n --slurpfile kdev kdev-public.jwk.json \
  '{devicePublicJwk: $kdev[0], platform: "IOS"}' > primary-init.json

curl -sS -X POST "$AUTH_BASE/api/v1/trusted-device/init" \
  -H "Authorization: Bearer $BFF_PRIMARY_INIT" \
  -H 'Content-Type: application/json' \
  --data-binary @primary-init.json
```

**200**

```json
{
  "success": true,
  "data": {
    "status": "KEY_EXCHANGE",
    "enrollmentId": "enr_primary_example",
    "challenge": "<base64url-challenge>",
    "expiresAt": "2026-11-03T03:05:00Z"
  }
}
```

### 2. POST /api/v1/trusted-device/verify

| Field | Kiểu | Ý nghĩa |
|---|---|---|
| `enrollmentId` | string, bắt buộc | ID trả về từ `/init` |
| `deviceProof` | string, bắt buộc | Chữ ký ML-DSA-65 raw, Base64URL không padding |

App dùng private Kdev ký đúng chuỗi UTF-8 `DCP-TRUSTED-DEVICE-VERIFY-V1:<challenge>`. Thay phần placeholder bằng challenge nguyên văn; dấu hai chấm thuộc tiền tố cố định. Không hash trước khi ký, không giải mã Base64URL, không thêm newline. Ví dụ với challenge rút ngắn: `DCP-TRUSTED-DEVICE-VERIFY-V1:XYZ12`.

Auth lấy challenge và public key từ enrollment đã ràng buộc với caller, dựng lại chuỗi và xác minh chữ ký. Request không gửi lại challenge hoặc public key. Chỉ một lần verify hợp lệ được quyền dùng challenge để tiến tới MFA; request đồng thời hoặc replay không được mở thêm MFA. Khi khởi tạo MFA thành công, Auth lưu giao dịch MFA gắn với đúng enrollment và trả `MFA_REQUIRED`. Nếu kết quả gọi MFA chưa rõ, không tự động gọi lại như một giao dịch mới. Verify thành công chưa làm thiết bị trusted.

```bash
# PRIMARY_DEVICE_PROOF do App/test signer tạo từ challenge trong response init.
jq -n --arg id "$PRIMARY_ENROLLMENT_ID" --arg proof "$PRIMARY_DEVICE_PROOF" \
  '{enrollmentId: $id, deviceProof: $proof}' > primary-verify.json

curl -sS -X POST "$AUTH_BASE/api/v1/trusted-device/verify" \
  -H "Authorization: Bearer $BFF_PRIMARY_VERIFY" \
  -H 'Content-Type: application/json' \
  --data-binary @primary-verify.json
```

**200**

```json
{
  "success": true,
  "data": {
    "status": "MFA_REQUIRED",
    "mfaTransactionId": "mfa_example",
    "expiresAt": "2026-11-03T03:08:00Z"
  }
}
```

`expiresAt` là hạn của bước MFA, giới hạn bởi hạn enrollment/phiên. App hoàn tất MFA theo contract nhà cung cấp hiện hành.

### 3. POST /api/v1/trusted-device/confirm

**Body:** chỉ có `enrollmentId` (string, bắt buộc). Auth kiểm tra đúng caller, enrollment đã chứng minh giữ khóa, và kết quả MFA hợp lệ cho đúng giao dịch. Sau đó Auth lưu binding với public key Kdev đã khóa ở init, áp dụng quy tắc primary hiện hành và hoàn tất enrollment. Chỉ trả thành công sau khi commit; confirm lặp không chạy lại mutation. Dữ liệu challenge không còn cần sau khi hoàn tất hoặc hết hạn.

Confirm **chỉ xác nhận trust**: không nhận `tokenEncryptionKey`, không cấp token mới và không nâng cấp hoặc gia hạn phiên restricted. App đăng nhập lại với proof mới nếu cần phiên `ACTIVE`.

```bash
jq -n --arg id "$PRIMARY_ENROLLMENT_ID" \
  '{enrollmentId: $id}' > primary-confirm.json

curl -sS -X POST "$AUTH_BASE/api/v1/trusted-device/confirm" \
  -H "Authorization: Bearer $BFF_PRIMARY_CONFIRM" \
  -H 'Content-Type: application/json' \
  --data-binary @primary-confirm.json
```

**200**

```json
{
  "success": true,
  "data": {
    "status": "TRUSTED",
    "enrollmentId": "enr_primary_example"
  }
}
```

### Lỗi và ca kiểm chứng của nhánh primary

| HTTP | Code | Tình huống |
|---|---|---|
| 400 | `REQUEST_REJECTED` | Public key, body hoặc encoding chữ ký không hợp lệ |
| 401 | `WRONG_CHALLENGE` | Chữ ký không khớp; áp dụng giới hạn lần thử hiện hành |
| 409 | `STATE_CONFLICT` | Sai bước, sai binding, challenge hết hạn/đã dùng hoặc confirm lặp |
| 409 | `MFA_NOT_PASSED` | MFA chưa hoàn tất |
| 401 | `MFA_FAILED` / `MFA_EXPIRED` | MFA thất bại hoặc hết hạn |
| 503 | Theo error catalogue hiện hành | Dependency lỗi hoặc chưa xác định được kết quả |

Mapping trên là đề xuất. Khi tích hợp, kiểm chứng vector App/Auth, sai khóa hoặc sai challenge, verify từ enrollment/phiên khác, replay và verify đồng thời, confirm trước MFA, và response confirm không có token.
