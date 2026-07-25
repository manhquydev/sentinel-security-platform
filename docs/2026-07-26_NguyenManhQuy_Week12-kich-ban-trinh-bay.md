# Kịch bản trình bày — Báo cáo Tuần 12

- Người trình bày: Nguyễn Mạnh Quý
- Đi kèm: `2026-07-26_NguyenManhQuy_Week12.md` (tài liệu nộp)
- Thời lượng: **12-15 phút nói + 3-5 phút hỏi đáp**

**Cách dùng file này:** phần 🗣 là lời nói — đọc được thành tiếng luôn. Phần 🖥 là thứ để
trên màn hình. Phần 💡 là ghi chú cho riêng em, không đọc.

Khối đánh dấu **[LÕI]** thì không được bỏ. Khối **[CẮT ĐƯỢC]** thì bỏ khi thiếu giờ.

---

## Chuẩn bị trước khi vào phòng

| Việc | Kiểm tra |
|---|---|
| Mở sẵn terminal, đã `cd` vào repo root | ☐ |
| Chạy `python -m agent.supervisor` lần thử trước | ☐ |
| Chuẩn bị đầu ra từ lần chạy gần nhất (11 findings + cost breakdown) | ☐ |
| Mở sẵn file `agent/finops.py` để chỉ chi phí (nếu bị hỏi sâu) | ☐ |
| Mở sẵn `docs/decisions/0017.md`, `0018.md`, `0025.md` ở tab riêng | ☐ |

> ⚠️ **Lưu ý:** `python -m agent.supervisor` cần gateway và các agent ready. Nếu stack chưa lên
> thì nó fail ngay. **Chạy thử trước.** Nếu không chạy được thì bỏ phần demo chạy live, mở
> thẳng output từ lần trước — đừng để fail live.

---

## PHẦN 1 — Mở đầu · 1,5 phút · [LÕI]

🖥 *Chưa cần gì trên màn hình. Nhìn lãnh đạo mà nói.*

🗣

> Em báo cáo Tuần 12 của Project Sentinel. Đây là tuần cuối, bàn giao toàn dự án.
>
> Trước tiên em phải nói rõ cái mà Sentinel **không** phải. Không phải "AI tự tìm ra lỗ
> hổng tốt hơn con người". Em đã chạy **13 lần đo đạc** — mỗi lần so AI với một phương pháp
> tất định, thì **AI hoặc thua, hoặc hòa, hoặc câu hỏi không trả lời được**. Con người không
> thay được bằng máy lúc này.
>
> Vậy nó là gì — rõ ràng. Nó là một **cỗ máy quét** kết hợp nhiều engine lại để tìm
> liên tục, cộng một **lớp bảo vệ cho chính con AI đang chạy** — để nó không bị lừa. Cái
> bảo vệ đó là cái mà đối thủ của chúng ta chỉ-tấn-công không có.

💡 *Chậm lại ở câu đầu. Để lãnh đạo thấm rõ: đây không phải bán huyền thoại AI.*

---

## PHẦN 2 — Ba trụ cột · 3 phút · [LÕI] ⭐ ĐIỂM CAO NHẤT

🖥 **Một bảng ba dòng, ba cột: Trụ cột | Con số | Có nghĩa gì.**

🗣

> Ba chỗ em muốn nói rõ về giá trị kinh doanh.
>
> **Trụ cột một: Tìm lỗ rẻ và liên tục.**
>
> Sentinel gộp hai engine quét — SAST tĩnh kết hợp DAST động. Một lần chạy, nó bắt được
> những lỗ hổng mà mỗi engine chỉ bắt được riêng lẻ. Kết quả: **recall tăng thêm 44%**.

🖥 *Chỉ vào con số 44% trên bảng.*

> Nhưng quan trọng là nó **không mất** phần chính xác. Con số precision giữ nguyên. Và
> **không tốn thêm tiền** — máy quét chạy liên tục, chi phí là compute, không có lệnh
> gọi AI. Nên chi phí phần này là **$0**.

💡 *Nói lại những con số: +44% recall, không mất precision, $0 chi phí. Lãnh đạo sẽ nhớ ba
con số này.*

> **Trụ cột hai: Chi phí lớp AI có trần.**
>
> Khi máy quét tìm được lỗ, AI phải kể lại bằng lời và phân loại. Chúng em chạy **ba lần
> live**, đo được chi phí thực từ bảng giá: **$0.048 đến $0.051 mỗi lần**.

🖥 *Chỉ vào con số $0.048–0.051.*

> Mỗi lần chạy mất khoảng 7.000 token và **35 giây**. **Zero lỗi** ở layer AI cả ba lần.
> Nên nói rõ: chi phí lớp này có trần.

💡 *Dừng một nhịp. Lãnh đạo sẽ so ngay với pentest $30.000. Mà $0.05 là cái chi phí
**mỗi lần**, không phải mỗi năm. Hãy để nó ngấm.*

> **Trụ cột ba: Lớp Security-FOR-AI.**
>
> Con AI của ta đang chạy để tấn công một ứng dụng. Nhưng chính nó cũng là mục tiêu. Ai
> đó có thể cố lừa AI bằng cách chèn lệnh độc vào mã nguồn mục tiêu mà ta đang quét, để
> AI sai lệnh.

🖥 *Vẽ hoặc chỉ sơ đồ: mục tiêu app → AI → lệnh sai.*

> Chúng em đơn giản hóa bảo vệ AI: **mọi input từ mục tiêu đều bị che thông tin nhạy cảm
> ngay lúc thu thập**, rồi mới đưa vào AI. Chúng em chạy **sáu tấn công tiêm lệnh** cố ý
> vào để kiểm tra — và **cả sáu tấn công đều bị chặn**.

🖥 *Chỉ vào con số 6/6.*

> Bên cạnh đó, mỗi lệnh từ người điều khiển đều được **gắn nhãn rõ ràng** và yêu cầu
> **quẹt thẻ xác thực OAuth2** — giống như nhân viên phải quẹt thẻ mới vào phòng. Nếu
> không thẻ, cửa **khóa mặc định** (không phải mở mặc định rồi từ từ khóa lại).
>
> Cái bảo vệ này — che PII, quẹt thẻ, khóa mặc định — là cái mà **đối thủ chỉ-tấn-công
> của chúng ta không có**. Họ chỉ biết tấn công, không biết bảo vệ chính con AI.

💡 *Đây là điểm bán cứng. Nó không chỉ là "an toàn hơn" — nó là cái khác. Nói chậm lại
ở câu này.*

---

## PHẦN 3 — So với pentest thủ công, nói cho đúng · 2,5 phút · [LÕI]

🖥 **Bảng so sánh hai cột: Pentest thủ công | Sentinel.**

🗣

> Một câu hỏi chắc lãnh đạo sẽ hỏi: nó thay được pentest không?
>
> Không. Và nó cũng không cố thay.
>
> Một đợt pentest thủ công hiện tại trên thị trường **khoảng $10.000 đến $35.000**.

🖥 *Chỉ vào con số đó.*

> Nó tốn **5 đến 15 ngày công** chuyên gia. Từ khi người khác nhận project đến khi giao
> report, mất **1 đến 4 tuần** lịch.

💡 *Nếu có người biết giá địa phương VN, cái số này sẽ khác. Nhưng framework so sánh thì
không đổi.*

> Pentest thủ công tìm được cái mà máy quét thường bỏ sót — là lỗi **logic nghiệp vụ**,
> lỗi **thiếu kiểm soát** (mà máy quét gọi là **absence** — thiếu cái gì đó). Nó là phần
> yêu cầu **con người** vì máy **bỏ mất** nó.

🖥 *Vẽ hay chỉ: người = tìm cái thiếu, máy = tìm cái sai.*

> Sentinel tìm được cái mà máy quét luôn giỏi — là lỗi **có mẫu xấu thật sự trong code**
> — gọi là **presence**. Nó **không thay người**. Nó **lấp khoảng mù**.
>
> Giữa hai đợt pentest thủ công cách nhau vài tuần, Sentinel chạy **liên tục**. Mỗi lần
> chạy chi phí ~$0.05 — nói cách khác, **tần suất gần như không bị chặn bởi chi phí**.

💡 *Nếu lãnh đạo tự nhẩm "$35k so với $0.05" thì phải chặn ngay: đó là so sai. Nói thẳng:
"Hai con số này không so trực tiếp được — pentest mua chiều sâu, Sentinel mua tần suất."
Và đừng quy ra chi phí năm: $0.05 là **ước tính từ bảng giá token**, không phải hóa đơn
(báo cáo mục 8 ghi rõ chưa đo được chi phí đô-la thực).*

> Điểm hòa vốn của Sentinel không phải từ "thay người", mà từ **dồn giờ người vào phần
> khó hơn**. Mỗi lỗi presence-class mà **máy quét bắt được** và AI **kể lại gọn gàng** là
> một lỗi người không phải rà tay. Đó là giờ tiết kiệm được.

💡 *Tuy nhiên: chúng ta chưa đo con số "giờ tiết kiệm mỗi finding". Nên không nêu nó như
một con số bán hàng. Ghi trong phần "chưa đo" ở phía sau.*

---

## PHẦN 4 — Kỹ thuật: IAM và Fuzzing, nói cho người không chuyên · 2,5 phút · [LÕI]

🖥 **Sơ đồ: Agent ← (quẹt thẻ) ← Gateway ← Fuzzing Engine.**

🗣

> Hai kỹ thuật em muốn giải thích bằng lời thường vì nó là phần lạ lẫm nhất.
>
> **Thứ nhất: Agent IAM — quẹt thẻ như nhân viên.**
>
> Con agent của ta cũng phải có danh tính, giống như nhân viên vào công ty. Nó không phải
> "cứ cho vào cho thoải mái", rồi từ từ quản lý. Nó là **cửa khóa mặc định** — chỉ khi
> nó quẹt thẻ hợp lệ (OAuth2) thì cửa mới mở. Người ta thường làm ngược lại — cửa mở
> sẵn, rồi "kiểm soát" ai vào. Nó **dễ bỏ sót**.
>
> Chúng em đo được: khi agent quẹt thẻ **hợp lệ**, gateway cho đúng những endpoint được
> phép. Khi agent quẹt **sai hoặc không quẹt**, gateway **không cho vào**. Nó không có
> tuỳ chọn "tạm thời mở". Và chúng em tìm ra **một cửa** chỉ có bảo vệ ở cổng, phòng
> bên trong không khóa — đó là **một lỗ rõ** mà chúng ta muốn khách thấy.

💡 *Quẹt thẻ là ẩu dụ quen thuộc. Lãnh đạo sẽ hiểu ngay. Không cần nói OAuth2 thêm.*

> **Thứ hai: Fuzzing — nhét rác có chủ đích.**
>
> Thay vì gõ lệnh đúng, ta **nhét những thứ vô nghĩa, những chuỗi tấn công cố ý** vào ô
> nhập để xem app có **vỡ ra, lộ thông tin** không. Báo lỗi chi tiết, stack trace, SQL
> injection, tất cả đều bị lộ khi ta nhét rác.

🖥 *Nếu có, chỉ ví dụ: nhét `'; DROP TABLE--` vào login ô, hoặc `../../../etc/passwd` để
lấy file hệ thống.*

> Sentinel **tự động làm việc này liên tục**, không cần con người. Mỗi lần chạy, nó ghi
> lại **chi phí** để không ai bị hóa đơn bất ngờ. Đây là cách giữ cho lỗ hổng không bỏ
> sót giữa hai đợt pentest.

---

## PHẦN 5 — Kịch bản demo trực tiếp · 3-4 phút · [LÕI]

🖥 **[NẾU CHẠY ĐƯỢC] Mở terminal, gõ:**
```
python -m agent.supervisor
```
**[NẾU KHÔNG CHẠY ĐƯỢC] Mở file kết quả từ lần chạy trước hoặc screenshot.**

🗣

> Em chạy thử trực tiếp ạ.
>
> Script này gọi **Supervisor agent** — nó điều phối ba engine con: **Recon** (khám
> phá target), **Fuzz** (nhét rác), **Exploit-sim** (mô phỏng khai thác). Tất cả đều
> được quán lý bởi một **Oracle** — một trọng tài tất định không dùng LLM (để đảm bảo
> công bằng).

💡 *Nếu chạy được, hãy chờ output. Nếu không, mở file output sẵn.*

🖥 **Khi output hiện ra: chỉ vào 11 findings.**

🗣

> Ra **11 findings** và **5 đề xuất khai thác**. Em xin cẩn thận chữ nghĩa ở đây: chúng
> **chưa phải lỗ hổng đã xác nhận** — hệ thống gắn nhãn `suspected-needs-hitl`, tức là
> "nghi ngờ, **chờ người duyệt**". Máy **không** tự phong cho mình quyền kết luận.
>
> Một chỗ em muốn chỉ riêng, và đây mới là finding đã xác nhận: **bảo vệ chỉ đứng ở cổng,
> phòng bên trong không khóa** — `gateway-only-enforcement`. Ai đi vòng qua cổng là vào
> thẳng. Cái này do **code tất định tìm ra, không phải AI** — đường ra phán quyết của
> chúng em **không có AI**, và có một bài test bắt buộc điều đó, để không model nào cãi
> mất một finding.

🖥 *Chỉ vào finding đó trong list.*

> Giờ chúng ta nhìn chi phí.

🖥 **Chỉ vào dòng chi phí hoặc mở `agent/finops.py`.**

🗣

> Toàn bộ lần chạy này — **11 findings + mô tả + phân loại + FinOps + audit log** — mất
> **$0.048 đến $0.051**. Mỗi lần quét một ứng dụng nhỏ-trung bình ra con số đó.
>
> Con số đó nhỏ tới mức **tần suất không còn là bài toán ngân sách** — chạy mỗi ngày hay
> mỗi lần commit đều không đổi bản chất chi phí.

💡 *Dừng một nhịp — nhưng KHÔNG mời lãnh đạo chia $35.000 cho $0.05. Phép chia đó ngụ ý
"mua 700.000 lần quét thay cho một đợt pentest", và dữ liệu của chúng ta không đỡ được
câu đó. Câu đúng để nói ra: "Rẻ tới mức ta chạy được liên tục — nhưng nó tìm lớp khác với
lớp mà pentest thủ công tìm."*

---

## PHẦN 6 — Chưa làm được — chúng ta nói thẳng · 2 phút · [LÕI]

🖥 **Bảng 10 khoảng trống từ mục 8 report.**

🗣

> Những gì chúng ta **không** đo được — và em nói thẳng chứ không giấu — để không ai
> mua nhầm kỳ vọng.
>
> **Chưa đo coverage toàn app** — em chỉ quét được phần qua cổng (8 endpoint). Nếu app
> có 100 endpoint, 92 cái còn lại không được kiểm tra. Nên em không hứa "bắt hết lỗ".
>
> **Chưa đo % lỗ absence thật** — lỗ thiếu kiểm soát. Em không biết Sentinel bắt được
> bao nhiêu % trong số đó, vì tiêu chuẩn chấm điểm không có. Đó là lý do em không thay
> pentest.
>
> **Chưa chạy IDOR, login, register thật** — những lỗ có nguy hiểm đổi trạng thái. Chạy
> thử trên target sống sẽ tốn thời gian setup HITL (con người ký duyệt). Em chưa làm.

💡 *Lãnh đạo nghe ba dòng đầu là hiểu rằng cái "11 findings" không phải là cái duy nhất,
và em biết điều đó. Nó nâng độ tin cậy của con số.*

> **Chưa đo giờ-người tiết kiệm mỗi finding** — này là con số **không được viết vào
> business case** của em. Vì nếu em bịa con số đó, khách sẽ mua nhầm kỳ vọng.
>
> Tất cả 10 khoảng trống này em ghi ra để chúng ta có một **bản đồ rõ** về cái gì đã
> đo, cái gì chưa. Đó là phần em tự hào nhất — không phải khoe kết quả, mà khoe cái em
> **không** biết.

💡 *Nó là phần khác Sentinel với một startup thổi phồng. Nói bình thản, không xin lỗi.*

---

## PHẦN 7 — Tại sao chọn Sentinel · 1,5 phút · [LÕI]

🖥 **Liệt kê tên các AI pentest competitor: XBOW, Pentera, RunSybil, Tenzai.**

🗣

> Trên thị trường có cái gì khác. XBOW, Pentera, RunSybil, Tenzai — tất cả là **offense
> only**: chúng tấn công. Cái nào cũng tốt, nhưng chúng **không bảo vệ chính con AI**.
>
> Bài toán của chúng ta là: **AI vừa là vũ khí (tấn công) vừa là mục tiêu** (người ta có
> thể lừa nó). Sentinel là cái duy nhất có **lớp defense** ngay trong quá trình tấn công:
> che PII, quẹt thẻ, khóa mặc định, HITL ký duyệt. Đó là **hào kinh tế** không phải khẩu
> hiệu.

💡 *Nó là cách nói "tại sao chọn chúng ta" mà không bô từ "*".

---

## PHẦN 8 — Đóng · 1 phút · [LÕI]

🖥 *Tắt màn hình chia sẻ hoặc quay lại slide đầu. Nhìn lãnh đạo.*

🗣

> Em tóm lại ba điều.
>
> Một: Sentinel **không phải AI tìm giỏi hơn con người**. Dữ liệu của chúng ta bác bỏ
> câu chuyện đó. Nó là máy quét **tây cơm** — chạy liên tục, **tìm lỗ rẻ**, giữ recall
> cao, để dồn giờ người vào cái **khó hơn**.
>
> Hai: Không thay được pentest, mà **lấp khoảng mù**. Pentest mua chiều sâu + phán đoán
> con người. Sentinel mua **tần suất** — ~$0.05 mỗi lần nên chạy được liên tục. Hai thứ
> này **cộng vào nhau**, không phải cái này trừ cái kia.
>
> Ba: Bảo vệ chính con AI đang chạy — lớp mà đối thủ chỉ-tấn-công **không có**. Đó là
> cái khác biệt.
>
> Và em muốn nói thêm: **10 thứ chúng ta chưa đo** ghi ở báo cáo không phải vì em chưa
> thông minh. Nó là bản đồ để chúng ta biết cái gì còn cần làm trước khi mở khóa tính
> năng mới.
>
> Em xin hết ạ.

---

# CHUẨN BỊ HỎI ĐÁP

💡 *Trả lời ngắn. Nếu không biết thì nói không biết — đừng đoán. Lãnh đạo kiểm tra được repo.*

### Q1. "Tại sao lại $0.05 chứ không miễn phí hẳn?"

> Vì phần AI — **kể lại và sắp xếp** — gọi model (chúng em dùng grok-4.5). Mỗi token có
> giá. Em đo được khoảng 7.000 token mỗi lần, quy ra $0.048–0.051.
>
> Phần máy quét (Semgrep + Nuclei) chạy local, **miễn phí**. Và em phải nói ngược lại điều
> lãnh đạo có thể đang nghĩ: **phần tìm ra lỗ là phần máy quét, không phải phần AI.**
> Chúng em đã **thử** để AI xác nhận và loại false-positive — **đo ra là không an toàn**:
> nó **bỏ mất 3 trong 8 lỗ thật**. Nên AI **không** được giao việc đó. Nó kể lại cho người
> đọc nhanh hơn, thế thôi. Đó là lý do $0.05 này là **chi phí tiện lợi**, không phải chi
> phí của năng lực phát hiện.
> Nên phí AI là chi phí tất yếu.
>
> Em có lựa chọn: dùng vLLM or Ollama chạy on-prem (mô hình local không tốn token). Nó
> là $0 token, nhưng phí GPU là tính riêng. Tuỳ khách chọn chi phí nào.

### Q2. "11 findings thì ít quá. Tại sao không bắt được nhiều hơn?"

> Con số 11 là **cái Sentinel bắt được** trên **8 endpoint** của target Juice Shop đã
> ghim. Nó không phải toàn bộ app. App có hơn 100 endpoint, chúng ta chỉ cover được 8
> cái qua cổng.
>
> Nếu muốn nhiều hơn, cách rẻ nhất là **mở rộng coverage** — khai báo thêm endpoint, hoặc
> **bật DAST sâu hơn** — để Fuzz engine tìm endpoint mới. Nó là việc tuần tới.

### Q3. "Nghe khoảng tin cậy $35.000 vs $0.05 — tại sao không thay hẳn pentest?"

> Vì **pentest tìm được cái máy quét không thấy được**. Giả sử một chuyên gia pentest
> ngồi vào app, chỉ dùng mắt và tay — anh ta sẽ tìm được logic lỗi mà không một công
> cụ quét nào phát hiện. Ví dụ: workflow thanh toán có thể bị bypass nếu gửi request
> theo thứ tự sai — máy quét chỉ gửi theo quy tắc, nó không suy nghĩ "thử điều gì nếu em
> bỏ qua bước này".
>
> Cái loại lỗi đó em gọi là **"absence"** — thiếu kiểm soát. Lỗ hổng không phải "có mà
> sai", mà là **"không có"**. Máy quét bỏ sót lớp này nhiều hơn khoảng **6.2 lần** so với
> lớp "có mà sai" — và đây là số **chính dự án em đo được**, chứ không phải em nghe ai nói.
>
> Nên xin nói cho thật rõ, kẻo hiểu ngược: **Sentinel KHÔNG lấp được lớp absence đó.** Nó
> chạy liên tục đúng phần máy quét **vốn làm tốt** (lớp presence), để **giải phóng giờ
> người** cho lớp absence. Người vẫn là người tìm lớp khó. Sentinel chỉ đảm bảo người
> không phải tiêu giờ vào phần lặp đi lặp lại.

### Q4. "Con số $0.048–0.051 — có phải là con số lạc quan không? Thực tế sẽ cao hơn?"

> Token và độ trễ là **đo chính xác** từ ba lần chạy live (khoảng 7.000 token, ~35 giây).
> Phần tiền là **quy đổi từ bảng giá của model chúng em dùng — grok-4.5**, chứ không phải
> hóa đơn thật. Em nói rõ chỗ này: đây là **ước tính có nguồn**, không phải con số kế toán.
>
> **Nhưng** nó chỉ áp dụng cho target nhỏ-trung bình (Juice Shop). Nếu target có 1 triệu
> dòng code, một lần quét sẽ sinh ra có lẽ 50 findings thay vì 11. AI phải xử lý nhiều hơn
> → token nhiều hơn → phí cao hơn. Nên nó không tuyến tính.
>
> Cách chắc chắn là: **chạy trên target thực của khách rồi đo**. Con số em nêu là
> **baseline**, không phải cái ghi bằng đá.

### Q5. "Tại sao em không gợi ý khách nên chạy mỗi ngày thay vì mỗi tuần?"

> Vì nó **tuỳ khách** chọn rủi ro. Nếu khách muốn coverage liên tục, chạy ngày. Nếu chỉ
> muốn check trước release, chạy tuần một lần. Mỗi lần chạy là $0.05, nên tính toán sẽ
> là: **bao nhiêu lần chạy = bao nhiêu phí**. Em không quyết định hộ.

### Q6. "Cái bảo vệ AI có thực sự chốt được tấn công hay chỉ chốt được test?"

> Chốt được **test tĩnh** — chúng em chạy **sáu payload tấn công** cố ý vào
> provenance-guard, cả sáu đều bị chặn. Nhưng đó là **tấn công tĩnh**, chưa thích ứng.
> Nếu ai đó tìm ra cách vượt qua nó bằng tấn công **thích ứng** — tức là cố tình thay đổi
> payload để vượt — thì chúng ta chưa biết.
>
> Em **không hứa** bảo vệ tuyệt đối. Em hứa **có lớp bảo vệ**, và nó **chặn được tấn công
> tĩnh đã biết**. Đó là vạch xuất phát tốt. Nếu người ta tìm được lỗ hổng mới trong lớp
> này, chúng ta sẽ sửa.

### Q7. "Khi nào thì em mở khóa được chạy IDOR, login, register thật?"

> Phải chờ **HITL (Human-In-The-Loop) ký duyệt** hoạt động liền mạch. Hiện tại nó **hoãn**
> — agent chỉ có thể ký lệnh trong một transaction cô lập, không thể thực sự sửa trạng
> thái database.
>
> Kỹ thuật là sẵn. Việc còn lại là setup để **người ký lệnh có đủ context** để quyết định
> "cái lệnh này có nguy hiểm không" trong vòng, chẳng hạn, 10 phút. Nó là việc tuần tới.

### Q8. "Tại sao không dùng một AI pentest khác mà dùng Sentinel?"

> Họ **chỉ tấn công**. Chúng ta **tấn công + bảo vệ** chính mình. Nếu khách chỉ cần
> tấn công, Pentera hay XBOW cũng được. Nhưng nếu khách lo lắng "AI của tôi bị lừa" —
> đó là bài toán của Sentinel.
>
> Còn về chi phí, em xin **không** so "$0.05 của mình với $4.000–8.000 một test của XBOW"
> — hai thứ đó không cùng phạm vi, so vậy là ăn gian. Cái em dám nói: chi phí lớp AI của
> Sentinel **có trần và đo được từng lần chạy**, nên khách biết trước mình trả cho cái gì.

---

# BẢN 10 PHÚT (khi bị cắt giờ)

Giữ đúng sáu khối này, bỏ hết phần còn lại:

| Khối | Thời gian | Nội dung |
|---|---|---|
| Mở đầu + ba trụ cột | 3,5 phút | Sentinel không phải "AI giỏi hơn". Ba trụ cột: +44% recall $0, $0.05/run, bảo vệ AI. |
| **So sánh pentest** | **2 phút** | $10k–35k vs $0.05. Không thay pentest, mà lấp cái lặp. Tần suất chứ không thay. |
| **Kỹ thuật IAM + Fuzzing** | **2 phút** | Quẹt thẻ như nhân viên. Nhét rác để xem vỡ. |
| Demo | 1.5 phút | Chạy supervisor → 11 findings → $0.05. |
| Chưa đo | 1 phút | 10 khoảng trống, không bịa. |
| Đóng | 30s | Ba điều: không phải AI giỏi; lấp cái lặp; bảo vệ chính AI. |

---

# BẢN 60 GIÂY (nếu chỉ được nói một đoạn)

> Sentinel là **máy quét chạy liên tục**, gộp nhiều engine để recall cao hơn 44%, chi phí
> $0. Cộng một **lớp bảo vệ cho chính con AI** — che PII, quẹt thẻ, khóa mặc định — cái
> mà đối thủ không có.
>
> **Không phải thay pentest** (không được), mà **lấp cái máy quét bỏ sót**. Mỗi lần chạy
> AI phân loại finding khoảng **$0.048–0.051**, tìm được 11 lỗi.
>
> **10 thứ chưa đo**: coverage toàn app, mẫu số recall lớp absence, giờ-người tiết kiệm.
> Em không bịa cái gì cả.
>
> Chi phí: pentest thủ công $10k–35k một đợt, mua **chiều sâu**. Sentinel ~$0.05 một lần
> chạy, mua **tần suất** — hai thứ cộng vào nhau chứ không thay nhau. Em không quy ra chi
> phí năm, vì $0.05 là ước tính từ bảng giá token chứ chưa phải hóa đơn thật.

---

# GHI CHÚ CUỐI

**Ba chỗ nói chậm lại:**
1. "Sentinel không phải AI tìm giỏi hơn con người" (Phần 1) — dừng một nhịp
2. "Chi phí lớp AI có trần $0.048–0.051" (Phần 2) — để lãnh đạo tự tính chi phí năm
3. "Không thay pentest mà lấp khoảng mù" (Phần 3) — nói rõ cái khác biệt

**Ba chỗ dễ sa đà, phải tự cắt:**
- Giải thích chi tiết SAST vs DAST → lãnh đạo không cần biết tên gọi
- Kỹ thuật gateway provenance → lãnh đạo chỉ cần biết "gắn nhãn"
- Cái nào model não — vành nhân → sẽ bị hỏi sâu, để Q&A

**Nguyên tắc xuyên suốt:** mỗi khi nêu con số đẹp, liền nêu luật chặn của nó. "11
findings nhưng chỉ 8 endpoint"; "$0.05 nhưng chỉ cho target nhỏ-trung bình"; "6/6 payload
bị chặn nhưng đó là tấn công tĩnh chưa thích ứng".

