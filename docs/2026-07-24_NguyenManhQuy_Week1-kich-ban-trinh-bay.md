# Kịch bản trình bày — Báo cáo Tuần 1

- Người trình bày: Nguyễn Mạnh Quý
- Đi kèm: `2026-07-24_NguyenManhQuy_Week1.md` (tài liệu nộp)
- Thời lượng: **12 phút nói + 5–8 phút hỏi đáp**

**Cách dùng file này:** phần 🗣 là lời nói — đọc được thành tiếng luôn. Phần 🖥 là thứ để
trên màn hình. Phần 💡 là ghi chú cho riêng em, không đọc.

Khối đánh dấu **[LÕI]** thì không được bỏ. Khối **[CẮT ĐƯỢC]** thì bỏ khi thiếu giờ.

---

## Chuẩn bị trước khi vào phòng

| Việc | Kiểm tra |
|---|---|
| Mở sẵn DefectDojo trên trình duyệt, đã đăng nhập, đang ở màn hình 2 Product | ☐ |
| Mở sẵn terminal, đã `cd` vào repo | ☐ |
| Thử chạy trước `bash scripts/verify-lake.sh` một lần cho chắc | ☐ |
| Mở sẵn file `runs/model-comparison.md` ở tab riêng (phòng khi bị hỏi sâu) | ☐ |
| Mở sẵn `scanners/out/semgrep.json.status.json` | ☐ |

> ⚠️ **Lưu ý:** `verify-lake.sh` cần DefectDojo đang chạy và có credential. Nếu stack chưa
> lên thì nó fail ngay ở bước xác thực. **Chạy thử trước.** Nếu không chạy được thì bỏ
> phần demo, mở thẳng file `lake-baseline.json` thay thế — đừng để fail live.

---

## PHẦN 1 — Mở đầu · 1 phút · [LÕI]

🖥 *Chưa cần gì trên màn hình. Nhìn mentor mà nói.*

🗣

> Em báo cáo Tuần 1 của Project Sentinel.
>
> Trước tiên em nói rõ phạm vi: **Tuần 1 không xây hệ multi-agent.** Tuần 1 xây cái nền
> cho 12 tuần.
>
> Cái nền đó có hai nửa. Nửa thứ nhất là một kho tổng hợp lỗ hổng — gom kết quả của nhiều
> công cụ quét bảo mật về một chỗ. Nửa thứ hai là đường ống AI-security, để sau này khi AI
> làm việc quét này thì chính nó không bị lừa.
>
> Và có một thứ xuyên suốt cả hai nửa, em muốn nói trước vì nó là bài học lớn nhất của em
> tuần này: **kiểu hỏng nguy hiểm nhất không phải là hệ thống báo lỗi. Mà là hệ thống báo
> thành công trong khi nó chẳng làm gì cả.** Phần lớn thời gian của em tuần này là xây các
> chốt để bắt đúng kiểu hỏng đó.

💡 *Câu cuối là cái mentor sẽ nhớ. Nói chậm lại ở câu đó, dừng một nhịp rồi mới đi tiếp.*

---

## PHẦN 2 — Cái nhìn thấy được · 2 phút · [LÕI]

🖥 **Mở DefectDojo.** Để màn hình danh sách 2 Product.

🗣

> Đây là kho. Em dùng DefectDojo — một hệ quản lý lỗ hổng mã nguồn mở.
>
> Hiện có 2 Product, mỗi Product là một ứng dụng. Cả hai đều là ứng dụng cố tình có lỗ
> hổng do OWASP phát hành: WebGoat và Juice Shop. Tổng cộng **36 lỗi thật**.
>
> Ba công cụ đưa vào đây, mỗi công cụ nhìn từ một góc khác nhau.
>
> Semgrep đọc mã nguồn tĩnh — nó bắt được 11 lỗi trong WebGoat, chủ yếu là dùng hàm sinh
> số ngẫu nhiên yếu.
>
> Trivy đọc image Docker — bắt được 4 lỗi, trong đó có 2 private key bị viết cứng.
>
> Nuclei thì gõ cửa app đang chạy thật — bắt được 21 lỗi, chủ yếu là thiếu security
> header.

🖥 *Chỉ tay vào Product `webgoat` trên màn hình.*

> Ở đây có một chỗ em muốn nói rõ, vì nhìn vào sẽ thấy nó **không cân**.
>
> `webgoat` chỉ có quét tĩnh, không có quét động. Lý do là em chưa ghim được bản chạy của
> WebGoat theo phiên bản cố định, nên chưa quét động được. Còn `juice-shop` thì có đủ, vì
> nó có image ghim mã băm và có app chạy thật.
>
> Sự không cân này là **cố ý và được ghi lại** trong quyết định số 7 của dự án. Em không
> giấu nó, vì nếu giấu thì tuần sau người khác nhìn vào sẽ tưởng WebGoat đã được quét
> động rồi.

💡 *Đừng đọc bảng số. Chỉ nói 3 con số: 11, 4, 21. Mentor tự cộng ra 36.*

---

## PHẦN 3 — Luồng 4 bước · 1,5 phút · [LÕI]

🖥 **Mở sơ đồ trong report** (mục 5), hoặc vẽ tay lên bảng nếu có.

🗣

> Một lần quét đi qua bốn bước: **quét — che — nhập kho — đối chiếu.**
>
> Bước quét: target phải nằm trong danh sách cho phép. Danh sách này **chặn mặc định** —
> cái gì không khai báo rõ ràng thì bị từ chối, chỉ địa chỉ loopback mới qua được. Việc này
> để chặn kiểu tấn công lừa hệ thống tự đi quét một địa chỉ nội bộ nào đó.
>
> Bước che: report thô có chứa giá trị secret thật, nên phải xoá đi.
>
> Nhưng ở đây có một chi tiết em làm sai lúc đầu và phải sửa lại.

💡 *Chậm lại. Đây là chi tiết cho thấy em hiểu công cụ chứ không chỉ chạy nó.*

> Em phải **xoá giá trị secret nhưng giữ nguyên vị trí lỗi.**
>
> Vì DefectDojo dựa vào vị trí — file nào, dòng nào, luật nào — để biết lỗi này đã có rồi
> hay chưa. Nếu em xoá luôn cả vị trí cho an toàn, thì mỗi lần quét lại DefectDojo sẽ
> tưởng đây là lỗi hoàn toàn mới, và số lỗi phình lên vô hạn.
>
> Nên nguyên tắc là: **xoá cái nhạy cảm, giữ cái để nhận dạng.**
>
> Hai bước còn lại là đẩy vào kho qua API bằng tài khoản không phải admin, và đếm lại đối
> chiếu với số đã ghim sẵn.

---

## PHẦN 4 — Hai chốt an toàn · 3 phút · [LÕI] ⭐ ĐIỂM CAO NHẤT

💡 *Đây là phần quan trọng nhất của cả buổi. Dành đủ thời gian. Đừng vội.*

🖥 **Mở file** `scanners/out/semgrep.json.status.json` — để nguyên trên màn hình suốt phần này.

🗣

> Phần này em muốn nói kỹ nhất, vì nó là chỗ phân biệt giữa "chạy công cụ" và "xây hệ
> thống đáng tin".
>
> Em kể một kịch bản hỏng trước.
>
> Giả sử em trỏ nhầm đường dẫn. Semgrep quét đúng **không** file nào. Nó trả về **không**
> lỗi nào. Hệ thống nhận kết quả đó và hiểu là *"tốt, không còn lỗi nào cả"*. Rồi nó đóng
> sạch toàn bộ lỗi cũ trong kho.
>
> Kết quả: mọi thứ **báo xanh**. Trong khi thực tế chưa có gì được sửa, và em thì không hề
> biết.

💡 *Dừng một nhịp ở đây. Để mentor thấm.*

> Đây là kiểu hỏng nguy hiểm nhất, vì nó không báo lỗi — nó báo thành công.
>
> Chốt thứ nhất em xây để chặn đúng cái đó, em gọi là **proof-of-contact** — bắt công cụ
> chứng minh là nó có thật sự chạm vào target.

🖥 *Chỉ vào file JSON đang mở.*

> Mỗi lần quét, công cụ phải xuất ra một file bằng chứng như thế này. Ở đây Semgrep khai
> báo là nó đã quét **296 file, 0 lỗi hệ thống**. Con số 296 chính là bằng chứng.
>
> Chỉ khi bằng chứng này hợp lệ, hệ thống mới được phép đóng các lỗi cũ. Nếu con số đó về
> 0, hệ thống vẫn nhập dữ liệu vào kho, nhưng **từ chối đóng lỗi cũ** và bật cảnh báo.
>
> Chốt thứ hai là ở bước đối chiếu. Logic thế này: target Juice Shop được ghim bằng mã băm
> sha256, bộ luật Semgrep được ghim bằng checksum. Cả hai đều không thể tự đổi.
>
> Nên số lỗi về lý thuyết **không thể tự thay đổi**. Nếu nó đổi, tức là có gì đó hỏng —
> chứ không phải "sai số chấp nhận được".
>
> Vì vậy bước đối chiếu so khớp **đúng bằng số**, không có ngưỡng dung sai.

🖥 **[NẾU CHẠY ĐƯỢC]** Chuyển sang terminal, gõ:
```
bash scripts/verify-lake.sh
```

🗣

> Em chạy thử luôn ạ.
>
> Script này chạy **7 kiểm tra**, và nó **chỉ đọc, không bao giờ ghi** vào kho — nhờ vậy
> nó không thể tự làm sai lệch thứ nó đang kiểm tra.
>
> Hai kiểm tra đầu chạy trên **toàn kho**, trước tất cả. Lý do là một baseline chỉ nhìn
> được những gì nó được bảo là hãy nhìn — nếu em chỉ kiểm tra từng Product có tên trong
> danh sách, thì một Product lạ nằm trong kho sẽ không ai đụng tới. Nên kiểm tra thứ nhất
> là: mọi Product **đang tồn tại thật** đều phải có tên trong baseline. Kiểm tra thứ hai
> là: không lỗ hổng nào trong toàn kho được trỏ vào corpus chấm điểm.
>
> Năm kiểm tra còn lại chạy cho từng Product. Ngoài việc so số đếm chính xác, nó còn bắt
> ba thứ mà chỉ đếm số thì không thấy được.
>
> Một là **engagement sinh nhầm**. Vì hệ thống bật chế độ tự tạo ngữ cảnh, nên gõ sai tên
> engagement sẽ âm thầm tạo ra một engagement anh em — và lỗ hổng nằm trong đó thì không
> ai kiểm tra. Nên sự tồn tại của nó đã là lỗi rồi.
>
> Hai là **thiếu hoặc thừa nguồn quét** — một công cụ chết âm thầm thì số của các công cụ
> khác vẫn đúng, nhìn vào không thấy gì bất thường.
>
> Ba là **độ tươi của dữ liệu**: lần nhập gần nhất không được cũ hơn 36 giờ. Em chọn 36
> giờ vì bộ hẹn giờ chạy mỗi ngày, cộng độ trễ ngẫu nhiên tối đa 1 tiếng, nên hai lần nhập
> hợp lệ có thể cách nhau tới 25 tiếng. 36 tiếng hấp thụ được dao động đó nhưng vẫn trượt
> nếu bỏ lỡ trọn một ngày. Và nó **mặc định là lỗi nghiêm trọng**, không phải cảnh báo —
> đúng theo nguyên tắc em nói lúc nãy: một kiểm tra không bao giờ kích hoạt được thì không
> phải kiểm tra.

💡 *Nếu không chạy được thì bỏ hẳn, mở `infra/defectdojo/lake-baseline.json` và nói: "số
được ghim ở đây, và script đối chiếu đúng bằng số này." Đừng cố debug trước mặt mentor.*

---

## PHẦN 5 — Nền AI-security · 2,5 phút · [LÕI]

🖥 **Sơ đồ phần AI-security** (mục 3 trong report).

🗣

> Sang nửa thứ hai. Phần này để các giai đoạn sau dùng lại.
>
> Mọi lời gọi model đều đi qua một cửa duy nhất là LiteLLM gateway. Nó làm ba việc: gắn
> nhãn nguồn dữ liệu, che secret ở đường ra, và ghi log.
>
> Gắn nhãn nguồn dữ liệu nghĩa là: đoạn nào là chỉ thị của hệ thống, đoạn nào là dữ liệu
> lấy từ target — tức là mã nguồn WebGoat, kết quả scan. Dữ liệu từ target được đánh dấu và
> bọc lại rõ ràng trước khi đưa vào model.
>
> Và đây là điều quan trọng nhất em phải nói.

💡 *Chậm lại. Đây là chỗ mentor sẽ đánh giá tư duy.*

> **Gateway này gắn nhãn. Nó không phát hiện prompt injection.**
>
> Đây không phải em làm thiếu. Đây là quyết định có lý do, ghi trong quyết định số 6.
>
> Lý do thứ nhất: các nghiên cứu về tấn công thích ứng đã phá được **12 phòng thủ dạng bộ
> lọc** đã công bố, với tỉ lệ thành công trên 90% — sau khi mỗi cái được báo cáo là "gần
> bằng 0" khi đo tĩnh. Nghĩa là bộ lọc tạo cảm giác an toàn giả.
>
> Lý do thứ hai, và nó đặc thù cho dự án này: lưu lượng **hợp lệ** của em *chính là* payload
> tấn công. Là chuỗi path traversal, là credential nằm trong mã nguồn cố ý có lỗ hổng, là
> chuỗi hex dài mà gần như luôn là file hash. Một bộ lọc đặt ở đây sẽ chặn nhầm liên tục.
>
> Nên Tuần 1 làm phần hạ tầng nhãn. Việc *thực thi* dựa trên nhãn đó thì để giai đoạn sau,
> khi có lớp phân quyền ở tầng agent.

### [CẮT ĐƯỢC — nhưng nên giữ nếu còn giờ]

🗣

> Và em không chỉ cấu hình phần này, em có **đo** nó. Hai phép đo.
>
> Phép đo thứ nhất trả lời một câu hỏi mà em tìm không thấy ai công bố: **bộ che secret có
> chặn nhầm nội dung bảo mật hợp lệ không?**
>
> Em cho 375 tài liệu thật đi qua nó. Kết quả: **0 trường hợp chặn nhầm rõ ràng.**
>
> Nhưng con số 0 đó chỉ có giá trị vì em chứng minh được cỗ máy này **có khả năng ra số
> khác 0**. Nếu em quay bộ nhận dạng JWT về phiên bản cũ, nó báo ngay **36 trường hợp chặn
> nhầm** — và em có một test khẳng định đúng con số đó. Trong 36 cái đó, chỉ 1 cái từng
> được phát hiện bằng mắt lúc review.
>
> Phép đo thứ hai là baseline tấn công tiêm lệnh, dùng bộ benchmark AgentDojo. Tỉ lệ tấn
> công thành công đo được là **0%**.
>
> Và em nói luôn: **con số 0% này gần như không có ý nghĩa về an toàn.** Nó chỉ có 2 tác vụ
> đủ điều kiện tính, tổng 6 lần chạy. Tấn công dùng ở đây là tấn công tĩnh, mà nghiên cứu
> đã chỉ ra tấn công tĩnh luôn thổi phồng độ bền — có bộ lọc đo được 0% tĩnh, khi bị tấn
> công thích ứng thì tỉ lệ thành công lên 64%.
>
> Nên em coi đây là **vạch xuất phát để Tuần 7 so trước-sau**, không phải bằng chứng an
> toàn.

---

## PHẦN 6 — Benchmark chọn model · 2,5 phút · [LÕI]

🖥 **Bảng 2 trong report** (mục 4.4).

🗣

> Phần cuối là đo lường bổ sung, không nằm trong yêu cầu bắt buộc của Tuần 1.
>
> Câu hỏi là: sau này AI-SAST sẽ đọc mã nguồn tìm lỗ hổng — **dùng model nào?** Em muốn trả
> lời bằng số đo, không bằng cảm nhận.
>
> Bộ đề là OWASP Benchmark: **2740 file Java, mỗi file có đáp án sẵn** — ghi rõ file này có
> lỗi thật hay không, và nếu có thì thuộc nhóm nào. Có đáp án nên chấm được bằng máy.
>
> Em đo 6 model. **Mỗi model chạy 3 lần độc lập** — vì kết quả của LLM không tất định, cùng
> một input chạy lại vẫn ra khác. Độ lệch giữa các lần chạy chính là thước đo độ không chắc
> chắn.
>
> Hai chỉ số chính, em nói bằng lời thường:
>
> **Precision** trả lời: *trong 100 lần model kêu có lỗi, bao nhiêu lần đúng?* Thấp thì kỹ
> sư mất thời gian truy báo động giả.
>
> **Recall** trả lời: *trong 100 lỗi có thật, model bắt được bao nhiêu?* Thấp thì lỗ hổng
> lọt qua.

🖥 *Chỉ vào dòng `sol` trong bảng.*

> Kết quả: em chọn `gpt-5.6-sol`. Precision 0.75, recall 0.93.
>
> Nó thắng baseline DeepSeek rõ ở **cả hai trục**, và vá đúng hai điểm yếu nặng nhất của
> DeepSeek. Nhóm lỗi về ranh giới tin cậy, DeepSeek **mù hoàn toàn** — recall bằng 0. `sol`
> lên được 0.65. Còn nhóm injection thì precision từ khoảng 0.5 lên 0.8–0.9.
>
> Và thứ tự xếp hạng giữa các model **không đổi** qua mọi cách chấm em đã thử. Đó là kết
> luận em tin.

💡 *Ba câu tiếp theo là phần mentor sẽ đánh giá cao nhất trong mục này. Nói rõ ràng, đừng
lướt.*

> Nhưng có **hai chỗ em phải nói thẳng là em không khẳng định được.**
>
> Thứ nhất, kế hoạch đặt mốc precision từ 0.75 trở lên là "dùng được cho production".
> `sol` đạt **0.7503** — hơn đúng ba phần mười nghìn. Khoảng tin cậy 95% của nó là từ 0.739
> đến 0.761, tức là **vắt qua mốc**. Riêng lần chạy đầu tiên còn nằm dưới mốc.
>
> Nên câu đúng phải là: **`sol` nằm ngay tại mốc, chưa vượt mốc.** Em không dám nói nó đạt
> chuẩn production.
>
> Thứ hai, con số precision 0.75 đó không phải cái người vận hành trải nghiệm. Nó là
> precision tính theo *đúng nhóm lỗ hổng*. Nếu tính ở mức **từng cảnh báo** — đúng cái mà
> kỹ sư triage phải ngồi xử lý — thì precision của `sol` chỉ là **0.573**.
>
> Cả hai con số đều hợp lệ, nhưng trả lời hai câu hỏi khác nhau. Em nêu cả hai chứ không
> chọn con số đẹp.

---

## PHẦN 7 — Chưa làm được · 1 phút · [LÕI]

🖥 **Bảng mục 7 trong report.**

🗣

> Những gì còn tồn lại.
>
> **ZAP chưa chạy live.** Em đã đấu nối xong và sửa cả phần che dữ liệu để sau này nhập
> được, nhưng chưa kéo được image trong đợt này.
>
> **Trivy chưa quét được CVE.** Lúc tải database lỗ hổng thì timeout, nên em chỉ chạy được
> phần secret và cấu hình sai. Phần rà thư viện phụ thuộc thì chưa có kết quả.
>
> **WebGoat chưa quét động được**, như em nói lúc đầu.
>
> Và một chỗ về benchmark: có một model tên `grok-4.5` cho **precision cao nhất trong tất
> cả model em đã đo**. Nhưng em mới chạy được 1 lần thì hết ngân sách API. **Một lần chạy
> không phải một kết quả** — nó không có độ lệch, không tách được khỏi nhiễu. Nên em ghi
> nhận đây là hướng đáng theo dõi, chưa đủ cơ sở để đổi. Chạy nốt 2 lần nữa là cách rẻ nhất
> để biến manh mối này thành kết luận.

💡 *Nói phần này bình thản, không xin lỗi. Nêu vấn đề kèm hướng xử lý là đủ.*

---

## PHẦN 8 — Đóng · 40 giây · [LÕI]

🖥 *Tắt màn hình chia sẻ hoặc quay lại slide đầu. Nhìn mentor.*

🗣

> Em tóm lại.
>
> Tuần 1 dựng xong nền cho cả hai nửa: kho lỗ hổng với 36 lỗi thật đã đối chiếu khớp, và
> đường ống AI-security đã có nhãn nguồn dữ liệu, có tracing, có hai baseline đo được.
>
> Nhưng thứ em học được nhiều nhất tuần này không nằm ở các con số đó.
>
> Em có ghi lại trong nhật ký kỹ thuật bốn chỗ em tự phát hiện mình đã làm sai. Trong đó có
> một mục em đặt tên là **"những bài kiểm tra pass vì chúng chẳng kiểm tra gì"** — em phát
> hiện có test luôn xanh, vì điều kiện của nó không bao giờ có thể sai.
>
> Riêng bảng benchmark cũng đã qua ba vòng review và bị sửa: bản đầu của em thổi phồng
> precision, hạ thấp recall, và khẳng định một điều mà chính dữ liệu của nó bác bỏ.
>
> Nên bài học của em là: **một bài kiểm tra không thể trượt thì không phải bài kiểm tra.**
> Và em nghĩ đó là thứ quan trọng nhất phải mang sang các tuần sau, khi hệ thống bắt đầu tự
> ra quyết định.
>
> Em xin hết ạ.

---

# CHUẨN BỊ HỎI ĐÁP

💡 *Trả lời ngắn. Nếu không biết thì nói không biết — đừng đoán. Mentor kiểm tra được repo.*

### Q1. "36 lỗi thì ít quá, WebGoat phải có hàng trăm lỗi chứ?"

> Đúng ạ. Con số 36 là **baseline đã ghim**, không phải toàn bộ lỗ hổng của hai ứng dụng.
> Lần chạy đầu Semgrep trên corpus benchmark ra 221 findings. Nhưng sau khi chuẩn hoá theo
> nguyên tắc *một Product là một ứng dụng* và tách corpus benchmark ra khỏi kho, baseline
> của WebGoat còn 11.
>
> Mục tiêu Tuần 1 là **đường ống chạy đúng và đếm đúng**, chưa phải phủ hết bề mặt tấn
> công. Muốn nhiều lỗi hơn thì thêm bộ luật và bật ZAP — đó là việc tuần sau.

### Q2. "Sao chỉ có mỗi Trivy chạy từ image ghim? Hai cái kia thì sao?"

> Thiết kế ban đầu là cả ba đều chạy từ image ghim mã băm. Thực tế chỉ Trivy làm được.
>
> Registry Docker trên máy em tải các layer lớn liên tục timeout — ZAP khoảng 1,6 GB đứng
> 40 phút không nhúc nhích, Nuclei và Semgrep chết ở layer cuối. Kết nối thì bình thường,
> nghẽn ở băng thông tải layer.
>
> Nên em cài Semgrep từ PyPI và tải Nuclei dạng binary từ GitHub release. Đây là đánh đổi
> **có chủ ý và được ghi lại** trong quyết định số 5, không phải bỏ qua yêu cầu. Target
> Juice Shop thì vẫn ghim mã băm đầy đủ.

### Q2b. "Bước che dữ liệu có làm mất lỗ hổng nào không? Sao biết?"

> Không mất cái nào ạ, và em kiểm tra được bằng số.
>
> Semgrep thô ra 11, sau khi che vẫn 11, vào kho 11, baseline ghim 11. Trivy 4 ở cả bốn
> chặng. Nuclei 21 ở cả bốn chặng. Tổng 36 không đổi.
>
> Nguyên tắc là **xoá giá trị, không xoá lỗ hổng**. Cái thay đổi là dung lượng file: báo
> cáo Trivy từ 636 KB xuống còn 2,2 KB — nhỏ đi 282 lần. Phần biến mất đó chính là nội
> dung dòng code quanh mỗi secret, thứ nguy hiểm nhất phải bỏ.
>
> Và cách che em cũng phải viết lại. Bản đầu dùng danh sách đen — liệt kê trường nào có
> secret rồi xoá. Cách đó rò qua mọi trường em chưa nghĩ tới. Bản hiện tại là danh sách
> trắng: chỉ giữ đúng những trường DefectDojo cần, còn lại bỏ hết. Khác biệt quan trọng là
> khi công cụ thượng nguồn thêm trường mới có secret, cách cũ sẽ giữ lại theo mặc định,
> cách mới bỏ đi theo mặc định.

### Q2c. "Khử trùng lặp thì kiểm tra ở đâu?"

> Ở `dd-smoke.sh`, tách riêng khỏi `verify-lake.sh`.
>
> Lý do tách rất cụ thể: muốn chứng minh "nhập cùng một lỗ hổng hai lần thì kho không
> phình" thì phải **ghi** vào kho. Mà một bước tên là "verify" thì tuyệt đối không được
> ghi — nếu không nó có thể tự làm sai lệch cái nó đang kiểm tra.
>
> `dd-smoke.sh` còn kiểm tra bốn thứ hạ tầng nữa: token CI chỉ có quyền trên đúng một
> Product, chế độ debug đã tắt và không khoá mã hoá nào còn giá trị mặc định, kết nối
> database thật sự là TLS và kết nối thường bị từ chối, và cả hai từ điển khử trùng lặp
> phải parse được với mọi khoá trỏ tới một loại scan đã đăng ký — vì gõ sai một khoá sẽ âm
> thầm rơi về parser mặc định.

### Q3. "Gateway không chống được prompt injection thì nó để làm gì?"

> Nó làm ba việc có ích ngay: che secret ở đường ra, ghi log audit, và gắn nhãn nguồn dữ
> liệu.
>
> Cái nhãn là phần quan trọng nhất về lâu dài. Nó là **điều kiện cần** để giai đoạn sau
> phân quyền được — kiểu "nội dung có nhãn *đến từ target* thì không được phép kích hoạt
> hành động ghi". Không có nhãn thì không thực thi được gì cả.
>
> Còn em cố ý không đặt bộ lọc phát hiện injection, vì bộ lọc dạng đó đã bị phá hết trong
> các nghiên cứu tấn công thích ứng, và với workload của em thì nó sẽ chặn nhầm liên tục —
> lưu lượng hợp lệ của em trông y hệt lưu lượng tấn công.

### Q4. "Precision 0.75 với 0.573 — rốt cuộc là bao nhiêu?"

> Cả hai đều đúng, chúng đo hai thứ khác nhau.
>
> **0.750** là precision tính theo *đúng nhóm lỗ hổng*: một cảnh báo sai nhóm trên file
> lành được tính là im lặng đúng. Nó đo **khả năng phát hiện đúng loại**.
>
> **0.573** là precision tính trên *từng cảnh báo*. Đây là cái kỹ sư trải nghiệm khi ngồi
> triage. Mỗi lần chạy có khoảng 345 cảnh báo sai nhóm như vậy.
>
> Nếu phải chọn một con số để ra quyết định vận hành thì em dùng **0.573**.

### Q5. "Sao không chọn `grok-4.5` khi nó precision cao nhất?"

> Hai lý do.
>
> Thứ nhất, nó mới chạy **1 lần**. Không có độ lệch giữa các lần chạy thì không tách được
> kết quả khỏi nhiễu. Một lần chạy là một mẫu, không phải một thứ hạng.
>
> Thứ hai, recall của nó thấp hơn `sol` khá nhiều — 0.830 so với 0.933. Với AI-SAST thì bỏ
> sót lỗ hổng nguy hiểm hơn là báo động giả.
>
> Em ghi nhận nó là hướng đáng theo dõi. Chạy nốt 2 lần nữa là việc rẻ nhất em có thể làm.

### Q6. "Sao mỗi model phải chạy 3 lần?"

> Vì LLM **không tất định**. Cùng một input, cùng nhiệt độ bằng 0, chạy lại vẫn ra kết quả
> khác.
>
> Nên độ lệch giữa các lần chạy chính là thước đo độ không chắc chắn chính. Chạy 1 lần rồi
> báo cáo là tự lừa mình — và đó cũng chính là lý do em không dám kết luận về `grok-4.5`.

### Q7. "Làm sao biết benchmark chạy đủ, không bị dở dang?"

> Em có **cổng đầy đủ**: không cho xuất điểm nếu số file đã quét khác 2740. Một lần chạy dở
> dang không bao giờ trở thành một "kết quả".
>
> Thêm một chốt nữa: nếu 10 lần quét liên tiếp không tốn token nào thì dừng ngay. Tín hiệu
> em chọn là **token**, không phải số lỗi tìm được — vì bộ đề có đoạn 41 ca liên tiếp không
> có lỗi, một model làm đúng sẽ trông y hệt một provider đã chết. Còn 0 token thì không có
> cách giải thích lành tính nào.

### Q8. "Bảng CWE em tự sửa — thế có phải chỉnh cho điểm đẹp lên không?"

> Câu hỏi đúng chỗ ạ. Em phân biệt rõ hai việc.
>
> Bảng ban đầu bắt model báo **chính xác** mã CWE mà bộ đề ghi. Nhưng cả 60 ca bỏ sót nhóm
> `weakrand` của `sol` đều được model báo là CWE-338 — mà CWE-338 chính là **con** của
> CWE-330 mà bộ đề ghi. Model làm đúng, bảng chấm sai. Cái đó em sửa.
>
> Còn những mã sẽ làm điểm đẹp lên mà không đúng bản chất thì em **từ chối**. Ví dụ CWE-1004
> cho nhóm `weakrand` — đó là một lỗ hổng *khác* tình cờ nằm cùng file. Lý do từ chối em ghi
> thẳng trong code của bảng ánh xạ.
>
> Và em áp bảng mới cho **tất cả** model, kể cả baseline, rồi công bố cả số trước và sau.

### Q9. "Repo có commit tới Tuần 8 rồi, sao báo cáo mới Tuần 1?"

> Đúng ạ. Đây là báo cáo **giai đoạn nền**. Các giai đoạn sau đã có code trên `main` và em
> sẽ báo cáo riêng từng phần. Em muốn phần nền được soi kỹ trước, vì mọi thứ sau đều dựa
> lên nó.

### Q10. "Tuần sau em làm gì?"

> Ba việc theo thứ tự ưu tiên.
>
> Một, đóng các lỗ hổng còn tồn: bật ZAP và lấy được database CVE cho Trivy — để mỗi
> Product có đủ cả góc tĩnh lẫn động.
>
> Hai, chạy nốt `grok-4.5` cho đủ 3 lần, để chốt lại lựa chọn model bằng dữ liệu chứ không
> để mở.
>
> Ba, bắt đầu lớp thực thi dựa trên nhãn provenance mà gateway đã sinh ra — vì hiện tại
> nhãn có rồi nhưng chưa ai dùng nó để chặn cái gì.

---

# BẢN 5 PHÚT (khi bị cắt giờ)

Giữ đúng bốn khối này, bỏ hết phần còn lại:

| Khối | Thời gian | Nội dung |
|---|---|---|
| Mở đầu | 45s | Tuần 1 là phần nền, hai nửa. Câu "hỏng nguy hiểm nhất là báo thành công". |
| Kho + demo | 1,5 phút | Mở DefectDojo, 3 con số 11/4/21, chạy `verify-lake.sh`. |
| **Chốt proof-of-contact** | **2 phút** | Kể kịch bản quét 0 file → đóng sạch baseline → báo xanh. Chỉ vào file bằng chứng 296 file. |
| Đóng | 45s | Chọn `sol` nhưng nó *ở* ngưỡng chứ chưa vượt. Bài học "test không thể trượt thì không phải test". |

---

# BẢN 60 GIÂY (nếu chỉ được nói một đoạn)

> Tuần 1 em dựng nền cho 12 tuần: một kho gom lỗ hổng từ 3 công cụ quét — hiện có 36 lỗi
> thật đã đối chiếu khớp chính xác — và đường ống AI-security gồm gateway gắn nhãn nguồn dữ
> liệu, tracing, cùng hai phép đo baseline.
>
> Phần em đầu tư nhiều nhất là các chốt bắt lỗi *im lặng*. Ví dụ nếu công cụ quét nhầm chỗ
> và trả về 0 lỗi, hệ thống sẽ tưởng đã sửa xong hết và đóng sạch baseline — mọi thứ báo
> xanh. Em bắt mỗi công cụ phải chứng minh nó có thật sự chạm target thì mới cho đóng lỗi
> cũ.
>
> Em cũng đã benchmark 6 model trên 2740 ca kiểm thử để chọn model cho AI-SAST. Em chọn
> `gpt-5.6-sol`, nhưng nói rõ là nó **nằm ngay tại** mốc chất lượng chứ chưa vượt — khoảng
> tin cậy của nó vắt qua mốc.
>
> Còn tồn: ZAP chưa chạy live, Trivy chưa quét được CVE.

---

# GHI CHÚ CUỐI

**Ba chỗ nói chậm lại:**
1. Kịch bản "quét 0 file → báo xanh" (Phần 4) — dừng một nhịp sau câu đó
2. "Gateway gắn nhãn, nó không phát hiện prompt injection" (Phần 5)
3. "`sol` nằm ngay tại mốc, chưa vượt mốc" (Phần 6)

**Ba chỗ dễ sa đà, phải tự cắt:**
- Đọc từng dòng bảng số → chỉ nói 2–3 con số mỗi phần
- Giải thích chi tiết cách hoạt động của Semgrep/Nuclei → mentor biết rồi
- Kể lể quá lâu về registry timeout → một câu là đủ, còn lại để Q&A

**Nguyên tắc xuyên suốt:** mỗi khi nêu một con số đẹp, nêu luôn giới hạn của nó. Đó là thứ
làm báo cáo này khác một bản khoe kết quả.
