# Báo cáo Tuần 12 — PRD, Business Case & Bàn giao — Project Sentinel (VinUni × VinSOC)

- Họ và tên: Nguyễn Mạnh Quý
- Tuần: 12 (tuần cuối)
- Ngày: 2026-07-26
- Phạm vi: đây là **PRD + business case** cho toàn dự án 12 tuần. Mọi con số trong báo cáo
  này là **số đo được**, dẫn nguồn tới file trong repo hoặc nguồn ngoài có ghi độ tin cậy.
  Chỗ nào chưa đo được thì ghi thẳng là chưa đo (mục 8), không suy đoán.

---

## 0. Tóm tắt cho lãnh đạo (một trang)

Sentinel **không phải** là "AI tự tìm ra nhiều lỗ hổng hơn con người". Qua 36 thí nghiệm
có đo đạc, mỗi lần em cho AI giữ **vai trò chốt chặn** (phán quyết, xác nhận, xếp hạng)
thì **AI hoặc thua, hoặc hòa, hoặc câu hỏi không trả lời được** — chi tiết ở mục 4. Bán
câu chuyện "AI tìm giỏi hơn" là bán thứ dữ liệu của chính dự án đã bác bỏ.

> **Ranh giới em phải nói rõ, kẻo chính em cũng nói quá:** kết luận trên đã đo **cho vai
> trò chốt chặn** (phán quyết / xác nhận / xếp hạng). Vai trò **đề xuất** (AI nêu giả
> thuyết, code tất định kiểm chứng) đo đêm 26/07, **lặp lại độc lập sáng 26/07**, và
> **kết quả ngược lại**: trên
> đúng lớp lỗ mà máy quét mù (thiếu kiểm soát — IDOR, thiếu rate-limit, thiếu authz),
> **Bandit + Semgrep tìm được 0/60 file**, còn LLM gọi đúng tên lớp lỗ ở **6/60 file
> (p = 0.0137)** — cùng một bộ file, nên không phải do "file này bẩn hơn".
>
> Đây là **năng lực đầu tiên trong dự án mà công cụ tất định không cung cấp được**. Và
> em đã kiểm tra tiếp hai câu hỏi quan trọng nhất:
> - **Có phải model chỉ "thấy code xấu là kêu"?** Không, và điều này đã **lặp lại độc lập
>   2 lần**. Trên 80 file có lỗ thật nhưng **không thuộc lớp thiếu-kiểm-soát**, model chỉ
>   kêu **2/80** — **không phân biệt được với file không có lỗi gì** (p = 0.44), trong khi
>   nhóm có lỗ thiếu-kiểm-soát là **14/59** (p = 0.00012). Lần đo đầu cho 0/80 vs 9/60
>   (p = 0.0003). Nó phân biệt **đúng lớp lỗ**, không phải phân biệt "bẩn/sạch".
> - **Có phải model chỉ đọc tên file/biến quen thuộc?** Không. Cùng một bộ file endpoint,
>   nhóm **thiếu** kiểm soát bị kêu 9/40 còn nhóm **có** kiểm soát chỉ 2/42 (p = 0.020),
>   và chạy lại độc lập cho kết quả lệch **0.026** (7/40 vs 1/42, chênh lệch +0.151, p = 0.024 —
>   vẫn có ý nghĩa thống kê, khoảng tin cậy vẫn không chứa 0).
> - **Có phải model chỉ học thuộc corpus public?** Đổi tên toàn bộ hàm/biến/route/tên file
>   (giữ nguyên ngữ nghĩa) → tỉ lệ phát hiện **không giảm** (11/53 → 14/53). Loại trừ
>   được "học thuộc bề mặt"; **chưa** loại trừ được mức đóng góp nhỏ.
> - **Trên code model chắc chắn chưa từng thấy** (tự viết ngay trong phiên, có đáp án
>   chính xác, 12 cặp / 3 framework): tìm được **7/12** lỗ cài sẵn, **1/12** báo nhầm
>   (p = 0.0136). Một audit độc lập sau đó phát hiện **2/12 bản "có kiểm soát" thực ra
>   vẫn thiếu control** — bỏ 2 cặp đó thì còn 7/10 và 0 báo nhầm (p = 0.0015). Em **trích
>   con số thận trọng (7/12)**, vì việc loại bỏ làm số đẹp hơn.
>
> **Vì sao vài con số ở trên khác bản trước:** chúng em đã đối chiếu lại toàn bộ kết quả đã lưu
> với **nguyên văn câu trả lời thô của model**, và phát hiện hồ sơ của chính mình đã lệch khỏi dữ
> liệu gốc. Sau khi sửa, **một con số chủ chốt của chúng em xấu đi** (15/59 → **14/59**) và con số
> kiểm chứng tên file cũng giảm (8/40 → **7/40**); một con số khác thì tốt lên. Kết luận không đổi
> ở cả ba trường hợp, nhưng em nói phần xấu đi trước — đó mới là phần lãnh đạo cần biết.
>
> **⚠️ GIỚI HẠN QUAN TRỌNG NHẤT — năng lực phụ thuộc LỚP LỖ, con số tổng che mất điều đó.**
> Trên bộ test có đáp án chính xác, model bắt **thiếu ownership 4/4** và **thiếu xác thực
> 2/2**, nhưng **miss hoàn toàn (0/4)**: thiếu rate-limit, mass assignment, lộ thông tin
> qua error, thiếu re-authentication. **CWE-307 (thiếu rate-limit) là lớp thiếu-kiểm-soát
> PHỔ BIẾN NHẤT trong corpus và bị miss ở cả hai lần thử.** Vì vậy quyết định 0027 đã thu
> hẹp: cái đo được là **thiếu ownership và thiếu xác thực**, không phải "các lớp
> thiếu-kiểm-soát" nói chung. Một hệ thống nghiêng về các lớp kia sẽ tệ hơn nhiều.
>
> **Cảnh báo trên ban đầu chỉ dựa trên 4 file do chính chúng em viết — quá mỏng để nói với
> lãnh đạo. Nay đã kiểm trên code thật.** Lấy toàn bộ **53 file trong corpus mang đồng thời
> cả hai loại lỗi** (thiếu ownership/xác thực *và* thiếu rate-limit), hỏi model một lần rồi
> đọc cả hai câu trả lời từ cùng một đoạn văn — nên không thể đổ cho "file này khó hơn file
> kia". Kết quả: model gọi tên được thiếu ownership/xác thực ở **6/53**, còn thiếu rate-limit
> chỉ **1/53**.
>
> Con số đáng nhớ nhất, và **không phụ thuộc phép so sánh nào**: cả 53 file đều có lỗi
> thiếu rate-limit **thật**, model chỉ nêu ra được **1**. Lớp lỗi phổ biến nhất trong corpus
> gần như **vô hình** với model ở vai trò này.
>
> Nói cho đủ: hiệu số +0,094 có khoảng tin cậy **[0,000 – 0,189]**, tức **chạm 0**. Nghĩa là
> hướng thì khớp với lần thử trước và cơ sở bằng chứng rộng ra từ 4 file lên 53 file, nhưng
> **chưa đủ để khẳng định**. Em đã tính trước công suất và biết là sẽ không đủ, nên công bố
> dưới dạng **ước lượng**, không phải kiểm định — và không ghi p-value để không ai đọc nhầm
> thành đã chứng minh.
>
> **Câu hỏi hiển nhiên tiếp theo — "thế thì hỏi thẳng model về rate-limit có được không?" — em đã
> thử và KHÔNG dựng được phép đo.** Khi hỏi thẳng "file này có thiếu giới hạn số lần đăng nhập
> không?", model trả lời **"thiếu" ngay cả với file đã có sẵn bộ giới hạn** ngay dòng trên. Nghĩa
> là câu hỏi mớm sẵn đáp án, và nếu em chỉ kiểm bằng một file mẫu (file thật sự thiếu) thì đã
> báo cáo "hỏi riêng thì phát hiện được" — một khuyến nghị sản phẩm **sai**. Em cài **hai** file
> mẫu đối chứng nên bẫy này lộ ra **trước khi** tốn một lời gọi nào trên dữ liệu thật.
>
> **⚠️ PHÁT HIỆN QUAN TRỌNG NHẤT TRONG NGÀY — chạy lại lần hai và ý nghĩa con số đã đổi.**
> Em chạy lại đúng 53 file đó lần nữa. **Tỉ lệ lặp lại chính xác tới từng con số** (6/53 và 1/53),
> và đây là lần đo thật chứ không phải cache — **52/53 câu trả lời khác nhau từng ký tự**. Nhưng:
> **6 file được phát hiện ở lần 1 và 6 file ở lần 2 KHÔNG TRÙNG FILE NÀO.**
>
> Nghĩa là cái lặp lại được là **tỉ lệ**, không phải **khả năng chỉ đúng file**. Model báo "thiếu
> ownership" ở khoảng 11% số file, nhưng không báo ở **cùng những file đó**. Với sản phẩm, hệ quả
> rất cụ thể: **chạy hai lần ra hai danh sách việc cần làm rời nhau hoàn toàn**, cùng tỉ lệ, và
> kỹ sư không biết tin danh sách nào. Muốn dùng thì phải **đọc lặp nhiều lần mỗi file** — và khi
> đó chi phí không còn là một lời gọi một file nữa — hoặc phải trình bày nó như một **phép lấy
> mẫu**, chứ không phải một máy quét.
>
> Em xin nói thẳng: đây là phát hiện làm **giảm giá trị bán được** của phần này nhiều nhất trong
> cả tuần, và nếu không chạy lại lần hai thì đã không ai biết.
>
> **Và em đã đo tiếp để biết vì sao — kết quả đổi luôn cách tính chi phí.** Đọc lặp lại nhiều lần
> trên cùng một file cho thấy **không phải xổ số**: file "có gì đó" thật sự dễ được nêu hơn. Nhưng
> **file cao nhất cũng chỉ 0,67**, tức **không file nào chắc chắn được phát hiện**. Con số cụ thể
> ở đoạn dưới, sau khi em đã đo rộng ra.
>
> Hệ quả rất cụ thể cho chi phí: một file có xác suất 0,33 thì đọc **1 lần** bắt được 33%, đọc
> **3 lần** bắt được **70%**, đọc 5 lần được 87%. Nghĩa là **muốn dùng được ở mức file thì bắt
> buộc phải đọc lặp**, và **mọi con số chi phí phải nhân với số lần đọc**. Một lời gọi một file
> chỉ mua được khoảng **một phần ba** những gì con số "tỉ lệ trúng" gợi ra.
>
> **Em đã đọc sâu và rộng thêm (3 lần chạy, 16 file) và kết quả sắc hơn — kèm một đính chính về
> cách hiểu con số 11%.** Nhóm file từng được phát hiện: **0,291**. Nhóm chưa từng: **0,021**.
> Chênh lệch **+0,271, khoảng tin cậy [0,104 – 0,437]**, tức **đã tách hẳn khỏi 0** (trước đó còn
> chạm 0). File tốt nhất đạt **0,667** — **không chạm tới 1**, nghĩa là **không file nào được phát
> hiện chắc chắn**, và giờ đây đó là số đo chứ không phải nhận xét.
>
> Con số nói rõ nhất bản chất: **7 trong 8 file thuộc nhóm chưa từng được phát hiện đứng đúng ở 0
> qua mọi lần đọc.** Không phải "ít khi được phát hiện" — mà là **không bao giờ**.
>
> **Và em đã đo được tỉ lệ đó trên cả 53 file — đây là con số quyết định giá trị thương mại.**
> Qua hai lần đọc độc lập, **41/53 file (77%, khoảng [64% – 87%]) chưa từng được nêu lần nào**.
> Đây là **cận trên**, vì file ở mức 0,33 thì hai lần đọc vẫn trượt cả hai với xác suất 44%. Hiệu
> chỉnh lại thì tỉ lệ thật vào khoảng **60–77%**.
>
> Nói thẳng ý nghĩa: **3–4 file trong 5 sẽ KHÔNG BAO GIỜ được nêu, dù đọc bao nhiêu lần.** Đọc lặp
> chỉ mua được phần còn lại, tức **nhiều nhất 1–2 file trong 5**, với chi phí nhân k, và **không
> biết trước đó là những file nào**. Đây là một sản phẩm **khác hẳn** với "bộ dò 11% chạy nhiều
> lần thì tốt lên" — và đây mới là mô tả đúng.
>
> **Riêng với lớp lỗi thiếu rate-limit thì con số còn nghiệt hơn: 52/53 file (98%) chưa từng được
> nêu lần nào qua cả hai lần đọc**, khoảng [90% – 99,7%]. Đây là con số có ý nghĩa quyết định nhất
> trong ngày, và nó là số đo trực tiếp, không cần hiệu chỉnh gì.
>
> **Em đã đo hẳn đường cong "đọc k lần thì được bao nhiêu" trên 5 lần đọc độc lập của cùng 53 file.
> Đây là bảng để tính giá:**
>
> | Đọc mấy lần | Số file nêu được | So với kỳ vọng lý thuyết |
> |---|---|---|
> | 1 lần | 5,2/53 (9,8%) | 100% |
> | 3 lần | 11,4/53 (21,5%) | 81% |
> | 5 lần | 15,0/53 (28,3%) | **70%** |
>
> **Không một file nào trong 53 file được nêu ở cả 5 lần đọc.** Đây là cách nói trực tiếp nhất,
> không cần mô hình, cho kết luận "không file nào được phát hiện chắc chắn".
>
> Ba điều phải đưa vào cách tính giá: (1) độ phủ **bão hòa rất sớm** — đọc 5 lần, trả tiền 5 lần,
> thấy 28% số file; (2) **lợi ích giảm dần đo được** — từ lần thứ 4 sang thứ 5 chỉ thêm 1,6 file;
> (3) **mọi cách tính kiểu "9,8% mỗi lần đọc, đọc k lần thì được k × 9,8%" đều SAI theo hướng
> tính đắt cho khách**.
>
> Nói thành lời chào hàng trung thực: **đọc mỗi file 5 lần, trả tiền 5 lần, thấy khoảng một phần tư.**
>
> Điểm đáng nói về cách làm: con số này em **không tốn thêm một lời gọi model nào** để có. Nó nằm
> sẵn trong dữ liệu đã lưu — hai lần chạy trước chính là hai lần đọc độc lập của cả 53 file. Nửa
> giờ trước em còn ghi nó vào danh sách "việc còn nợ, cần chạy thêm".
>
> **Đính chính quan trọng:** con số 11% **không có nghĩa là "mỗi file có 11% cơ hội được phát
> hiện"**. Thực tế là **phần lớn file gần như bằng 0**, và một thiểu số nằm ở mức 33–67%. Số 11%
> là trung bình của một tập mà **hầu như không file nào giống cái trung bình đó**.
>
> Nói theo ngôn ngữ bán hàng cho đúng: đọc lặp **thật sự có tác dụng**, nhưng **chỉ trên phần file
> có tín hiệu**, và **không vượt được trần của chúng**. File ở mức 0 thì đọc bao nhiêu lần cũng
> không ra. Lời hứa trung thực là: **phủ được một phần corpus, với chi phí nhân k, và không biết
> trước phần đó là phần nào.**
>
> **Cách thử thứ hai, và nó khép lại vấn đề:** thay vì đổi câu hỏi, em bỏ hẳn phần tranh chấp —
> chạy đúng câu hỏi cũ trên **16 file chỉ có mỗi lỗi thiếu rate-limit**, không có lỗi nào khác
> giành chỗ. Kết quả **1/16**, so với 1/53 lúc có tranh chấp: **không cải thiện** (p = 0,41). Đáng
> chú ý là nhóm 16 file này lại **nhỏ hơn hẳn** (84 so với 189 dòng), tức là *dễ hơn* — điều kiện
> đã nghiêng về phía có lợi cho giả thuyết "model thấy được nhưng không thèm nói", vậy mà vẫn
> không thấy. Kết luận thực dụng: **đây không phải lỗi cách hỏi, và "prompt khéo hơn" không phải
> là lời giải.** (Chỉ loại được hiệu ứng lớn; hiệu ứng nhỏ thì corpus không đủ file để kết luận.)
>
> **Và vẫn chưa bán được:** tỉ lệ trúng ~24% (bỏ sót 3/4; đây là **sàn**, vì bộ phân loại đếm thiếu), 1/3 lượt model không trả
> lời, chỉ ở mức file chứ không ra dòng, và vẫn **chưa test trên target model chắc chắn
> chưa từng thấy**. Vì vậy: đây là **kết quả nghiên cứu + hướng đi**, chưa phải tính năng
> bán cho khách (quyết định 0027).

Vậy Sentinel là gì, nói thẳng bằng một câu:

> Một **cỗ máy quét tất định** làm phần "tìm" (đo được: gộp nhiều engine nâng recall
> **+43.6%, KTC [+31.5%,+58.4%], miễn phí**), cộng một **lớp bảo vệ cho chính con AI** (Agent IAM, cổng xuất
> xứ, che PII, chốt người-duyệt) mà các đối thủ chỉ-tấn-công **không có**, và AI chỉ
> làm phần **kể lại + phân loại** với chi phí đo được **~$0.05/lần chạy**.

Giá trị kinh doanh nằm ở ba chỗ, tất cả đều có số:

| Trụ cột | Số đo được | Nguồn |
|---|---|---|
| **Tìm lỗ rẻ và liên tục** | Gộp 2 engine → recall **+43.6%** tương đối, **KTC 95% [+31.5%, +58.4%]** (bootstrap trên 63 repo), **không đo được tổn thất precision so với Bandit, $0** | decision 0022, E15 |
| **Chi phí lớp AI có trần** | 3 lần chạy live: **$0.048–0.051/lần**, ~7k token, ~35s, 0 lỗi | E13, `agent/finops.py` |
| **Lớp Security-FOR-AI** | Che PII: **6/6** payload injection bị chặn, **0** false-positive rõ ràng (corpus 375 tài liệu); IAM fail-closed | decision 0017, 0025 |

> **Giới hạn phải nói kèm con số +43.6%:** đó là mức trung bình **trên cả danh mục 63 repo**.
> **22/63 repo (35%) không được lợi gì cả** — thêm engine thứ hai ra kết quả đúng bằng engine thứ nhất.
> Vì vậy chỉ được hứa ở mức **danh mục**, **không** được hứa "app nào của anh cũng tăng 44%".

So với một đợt pentest thủ công (thị trường 2025–2026: **$10.000–35.000**, **5–15 ngày
công**, **1–4 tuần** lịch — nguồn có dẫn ở mục 5), Sentinel **không thay thế** người
kiểm thử. Nó **gánh phần lặp đi lặp lại** (lớp "presence" — mẫu xấu có thật trong code)
chạy liên tục với chi phí gần như bằng compute, để **dồn giờ người** cho lớp mà máy đo
được là mình **bỏ sót** (lớp "absence" — thiếu kiểm soát; khoảng cách **6.2×**, và
benchmark SAST chuẩn **chứa 0% ca thuộc lớp này** — mục 4).

**Ba điều em muốn lãnh đạo chú ý nhất:**
1. Con số bán hàng trung thực ở đây là **chi phí và trần**, không phải "độ giỏi của AI".
2. Điểm khác biệt sống còn so với XBOW/RunSybil/Tenzai: họ chỉ tấn công; Sentinel là thứ
   duy nhất **bảo vệ luôn con AI đang tấn công** — đúng bài toán "AI vừa là vũ khí vừa là
   mục tiêu".
3. Có **10 thứ chưa đo** (mục 8). Chúng em ghi ra để không ai mua nhầm kỳ vọng.

---

## 1. Bài toán & người dùng

**Người dùng:** đội pentest của VinSOC, làm trên web app của khách hàng / công ty — nơi
chúng ta **kiểm soát mã nguồn và tài liệu** (đã xác nhận qua vòng advise).

**Nút thắt thật (họ tự chọn):** *coverage* — lỗ hổng **bị bỏ sót hoàn toàn**, không phải
false-positive. Một đợt pentest thủ công sâu nhưng **tốn tuần và tiền**, nên không thể
chạy liên tục; giữa hai đợt là khoảng mù.

**Sentinel giải cái gì:** phần kiểm thử **lặp lại được** thì để máy chạy **liên tục và
rẻ**, giữ recall cao bằng cách gộp nhiều engine, và **đóng khung trung thực** phần máy
không làm được để người tập trung vào đó.

---

## 2. PRD — Sentinel làm được gì (đã build, đã đo)

Đây là hợp đồng sản phẩm. Mỗi dòng là năng lực **đã có code + có test/đo**, không phải
kế hoạch.

| # | Năng lực | Trạng thái | Bằng chứng đo được |
|---|---|---|---|
| P1 | **Kho lỗ hổng đa nguồn** (SAST/DAST về một chỗ, không đếm trùng) | Đã build (Tuần 1) | 3 công cụ, 36 lỗ, 7 bước kiểm tra khớp |
| P2 | **Gộp nhiều engine tất định** | Đã build & đo | recall **+43.6%** [+31.5%,+58.4%] (tuyệt đối 0.188 — vẫn sót ~81%), không đo được tổn thất precision **so với Bandit**, $0; **22/63 repo không lợi gì** (0022, E15) |
| P3 | **Cổng xuất xứ LiteLLM** (mọi lời gọi model gắn nhãn `operator`/`target-derived`, fail-closed nếu thiếu) | Đã build | test cổng 30/31 pass; SAIST bên thứ ba **không** kết nối qua được (E11) |
| P4 | **Kong Agent IAM** (OAuth2 + ACL fail-closed cho agent) | Đã build & đo | 29/29 test authz; 1 finding gateway-only-enforcement (decision 0025) |
| P5 | **Che PII lúc thu thập** | Đã build & đo | 6/6 payload tấn công bị chặn; 0 FP rõ ràng; 37/371 tài liệu WebGoat bị che (84 chỗ) (decision 0017) |
| P6 | **Multi-agent syndicate** (Supervisor→Recon→Fuzz→Exploit-sim) | Đã build | 30/30 test syndicate; chạy live ra 11 finding, 5 đề xuất |
| P7 | **Chốt người-duyệt (HITL) ngoài tiến trình, ký Ed25519** | Đã build | thiết kế fail-closed (decision 0016); hành động đổi-trạng-thái vẫn **hoãn** (mục 8) |
| P8 | **FinOps theo từng lần chạy** | Đã build & đo | $0.048–0.051/lần, ~7k token, ~35s (E13) |
| P9 | **Đóng gói + phục vụ on-prem** | Đã build | image ~340 MB non-root; vLLM/Ollama path $0/token (decision 0019) |
| P10 | **Oracle chấm điểm tất định** (không dùng LLM làm trọng tài) | Đã build & đo | LLM-làm-trọng-tài **từ chối 12/12 lần** — nên bị loại khỏi đường phán quyết (decision 0018) |

**Ranh giới sản phẩm (không mơ hồ):** đây là bản **nghiên cứu/giáo dục**, chạy loopback
sau allowlist chặn mặc định. Không phải sản phẩm thương mại; kết quả bó trong phạm vi
đo được ở mục 8.

---

## 3. Kiến trúc — hai nửa

**Nửa tấn công (offense):** kho đa nguồn → gộp engine tất định → syndicate recon/fuzz →
oracle tất định chấm → AI kể lại + phân loại.

**Nửa phòng thủ cho AI (Security-FOR-AI, phần đối thủ không có):** mọi lời gọi model qua
cổng xuất xứ; agent có danh tính OAuth2 + ACL fail-closed; PII bị che ngay lúc thu thập;
hành động nguy hiểm phải qua người ký duyệt; guard chống prompt-injection cấu trúc.

Nguyên tắc xuyên suốt, **đo chứ không tin**: fact do code sinh ra thì gánh trọng lượng;
lời AI chỉ để kể. Đường phán quyết **không có LLM** — một test cấu trúc bắt buộc điều đó
(DD1), vì "không component nào được cãi mất một finding".

---

## 4. Định vị trung thực — vì sao KHÔNG bán "AI tìm giỏi hơn"

Đây là phần quan trọng nhất và là phần dễ bị bỏ qua nhất. Mọi so sánh AI-với-tất-định mà
dự án đã đo **ở vai trò chốt chặn** đều kết thúc bất lợi cho AI:

| Thí nghiệm | Giả thuyết "AI thắng" | Kết quả đo | Nguồn |
|---|---|---|---|
| LLM làm trọng tài chấm đúng/sai | AI phán quyết được | **Từ chối 12/12** dưới xuất xứ đúng | decision 0018 |
| LLM verifier lọc false-positive | AI bỏ FP, giữ lỗ thật | **Bỏ mất 3/8 lỗ thật** (38% mất recall) | decision 0020 |
| LLM annotator xếp hạng | AI hơn tiên nghiệm CWE | **Thua** — xếp hạng trong từng app: tiên nghiệm CWE miễn phí **+0.095 [+0.063,+0.128]**; gộp chung mọi app thì hòa | 0021, E14 |
| Lớp LLM trong syndicate | AI tìm ra lỗ mà tất định bỏ sót | **0 finding thêm**, +$0.05 & +35s/lần | E13 |
| AI-SAST bên thứ ba (SAIST) | Cắm vào là chạy | **Không kết nối** qua cổng xuất xứ; **thoát mã 0 dù lỗi 500** | E11 |

**Bài học một câu:** mọi chiến thắng sạch trong dự án đến từ **thêm công cụ tất định**,
chưa lần nào đến từ **thêm một model** — *ở vai trò chốt chặn*. Vai trò **đề xuất** còn để ngỏ
(E16/E17), và đó là hướng nghiên cứu tiếp theo chứ không phải điều đã chứng minh.

Và luật đo được về khoảng mù: SAST phát hiện **sự hiện diện** của mẫu xấu tốt hơn **sự
vắng mặt** của kiểm soát khoảng **6.2×** (decision 0023 — *đã sửa từ 9.5× sau khi tự tìm
ra lỗi gán CWE sai 61%*), và benchmark SAST chuẩn **chứa 0% ca thuộc lớp vắng-mặt**
(decision 0024). Nghĩa là lớp "absence" không phải bị đo kém — nó **không được đo**. Đó
đúng là chỗ giờ-người phải vào. (Câu "absence là nửa LỚN hơn" đã bị **rút lại** ở 0023 sau khi sửa
lỗi gán CWE — tỷ lệ hai nửa hiện **chưa xác định**; điều đứng vững là con số **0%**.)

> ⚠️ Ghi chú cho người viết slide: nghiên cứu ngoài (arxiv) có bảng "LLM F1 0.75 vs SAST
> 0.26". **Không trích** con số đó như thành tựu của Sentinel — nó **mâu thuẫn** với dữ
> liệu tự đo của chính dự án. Dùng số của mình.

---

## 5. Business Case — ROI so với pentest thủ công

### 5.1. Chi phí pentest thủ công (thị trường 2025–2026, có dẫn nguồn)

| Hạng mục | Con số | Độ tin cậy / nguồn |
|---|---|---|
| Một đợt pentest web tiêu chuẩn | **$10.000–35.000** | nhiều nguồn 2025–2026 (đã dẫn ở report thị trường) |
| Phạm vi nhỏ | $5.000–10.000 | Blaze InfoSec 2026, FireCompass 2025 |
| Ngày công chuyên gia | $1.000–2.500/ngày | các guide 2025–2026 |
| Thời lượng | 5–15 ngày công; 1–4 tuần lịch | Fortbridge 2026, FireCompass 2025 |
| Vá lỗi (MTTR High/Critical) | 54–74 ngày | Edgescan 2025 |
| Đông Nam Á (tham chiếu) | $5.000–50.000 (dải rộng) | Qualysec 2025 — **nên lấy báo giá địa phương để chốt** |

### 5.2. Chi phí Sentinel (số tự đo)

| Hạng mục | Con số | Nguồn |
|---|---|---|
| Một lần chạy syndicate có LLM | **$0.048–0.051** (ước tính token × bảng giá) | E13, `agent/finops.py` |
| Một lần chạy tất định (không LLM) | **$0** lời gọi model | E13 |
| Phục vụ on-prem (vLLM/Ollama) | **$0/token** (chi phí GPU hạch toán riêng) | decision 0019 |
| Ngân sách chốt cứng/lần | $1/lần (cảnh báo khi vượt) | decision 0019 |
| Image agent | ~340 MB | `infra/agent/` |

### 5.3. So sánh — nói cho đúng, không thổi

**Không** phải "$0.05 thay cho $30.000". Đó là so sai. So đúng:

- Pentest thủ công mua **chiều sâu + phán đoán con người** — tìm lớp business-logic và
  absence mà máy đo được là mình bỏ sót. **Không thay được**, và Sentinel không cố thay.
- Sentinel mua **tần suất**: chạy phần presence-class **liên tục**, chi phí ~compute.
  Nói cho đúng: gộp 2 engine **tăng recall thêm 43.6% tương đối** so với 1 engine, nhưng
  recall **tuyệt đối vẫn chỉ 0.188** — tức là **vẫn bỏ sót ~81% lỗ thật**. Đây không phải
  "recall cao"; đây là "rẻ nên chạy được liên tục". Giữa hai đợt pentest thủ công tốn-tuần,
  **khoảng mù được lấp một phần**, không phải được lấp hết.
- **Điểm hòa vốn** không đến từ thay người, mà từ **giảm số giờ người tiêu vào việc
  lặp**: mỗi finding presence-class máy đã bắt và AI đã phân loại là một finding người
  không phải rà tay. (Số giờ tiết kiệm/finding: **chưa đo** — mục 8, không được bịa.)

### 5.4. Neo rủi ro (để định giá phòng ngừa)

Chi phí một vụ lộ dữ liệu trung bình toàn cầu **$4,44 triệu** (IBM/Ponemon 2025); Mỹ
$10,22 triệu; y tế $7,42 triệu; $160/bản ghi. **Không** có con số "giá của một lỗ bị bỏ
sót" đơn lẻ đáng tin — dùng các số này làm **neo phòng ngừa**, không trình bày như tổn
thất trực tiếp.

### 5.5. Vì sao chọn Sentinel thay vì một AI-pentest chỉ-tấn-công

XBOW ($4.000–8.000/test), Pentera ($50k–100k+/năm), RunSybil, Tenzai — tất cả là
**offense-only**. Không cái nào giải bài "**bảo vệ con AI đang chạy tấn công**". Sentinel
là lớp Security-FOR-AI đó: IAM cho agent, cổng xuất xứ fail-closed, che PII, HITL ký số.
Đây là **hào kinh tế** thật và **đo được** (P3–P7), không phải khẩu hiệu.

---

## 6. Giải thích cho người không chuyên (dùng khi trình bày)

**Agent IAM (Kong) là gì — nói như đời thường:** con AGV/agent của ta cũng phải **quẹt
thẻ** như nhân viên. Không thẻ → **cửa đóng mặc định** (fail-closed), không phải "cứ cho
vào cho tiện". Ta đo được: khi agent quẹt thẻ hợp lệ, cổng cho đúng phần được phép; và
tìm ra **một cửa** mà bảo vệ đứng ở cổng nhưng phòng bên trong không khóa — đúng loại lỗi
"một điểm chết" mà ta muốn khách thấy.

**Fuzzing là gì:** thay vì gõ đúng mật khẩu, ta **nhét đủ thứ rác có chủ đích** vào ô nhập
để xem app có **vỡ ra thông tin** không (báo lỗi lộ stack, chèn SQL...). Sentinel làm việc
này **tự động, liên tục**, và mỗi lần chạy đều **ghi lại chi phí** để không ai bị hóa đơn
bất ngờ.

**Xuất xứ (provenance):** mỗi câu đưa cho AI đều dán nhãn "**đây là lệnh của ta**" hay
"**đây là chữ do mục tiêu nhả ra**". Nếu không có nhãn, cổng **từ chối**. Đây là cách ta
chặn mục tiêu **giả giọng người điều khiển** để lừa AI.

---

## 7. Bàn giao & vận hành

- **Mã & test:** 19 bộ test; 17 xanh ở phiên này (2 đỏ là **trôi hạ tầng live**, tái hiện
  y hệt ở `origin/main` — không phải hồi quy do code tuần này).
- **Quyết định lưu vết:** 0017–0025 trong `docs/decisions/`, có index.
- **Sổ lab:** `docs/ai-sast-research-log.md` — E1–E13 kèm mọi lần tự sửa sai.
- **Nhánh:** `feat/week10-11-eval-finops-and-ai-sast-research` (PR #12, phụ thuộc PR #11).
- **Chạy lại:** baseline chấm điểm tái lập offline từ JSON đã commit, **không cần** gateway.

---

## 8. Chưa làm được — nói thẳng, không bịa (10 khoảng trống)

| Chưa đo | Hệ quả — điều **không** được hứa với khách |
|---|---|
| Chi phí đô-la thực/lần (chỉ có ước tính từ bảng giá) | Không hứa con số hóa đơn |
| Coverage toàn app (chỉ đo được phần qua cổng) | Finding bó trong 8 endpoint routed |
| Mẫu số recall lớp absence | Không biết % lỗ authz thật mà syndicate bắt được |
| An toàn probe đổi-trạng-thái (HITL còn hoãn) | Chưa chạy IDOR/login/register thật trên target sống |
| Verifier trên toàn 63 repo (mới chạy 3) | Không hứa an toàn LLM-verifier trên cả corpus |
| Đa ngôn ngữ (mới Python) | Không hứa recall cho Go/Ruby/JS |
| Khái quát hóa họ model (mới 2 model) | Không hứa "mọi model đều từ chối đúng" |
| DAST sâu ngoài read-only | Không định lượng phần "absence" syndicate thật sự lấy lại |
| Độ trễ dưới tải production | Số một-lần-chạy, chưa có đồng thời/scale |
| Hiệu năng vLLM on-prem trên GPU thật | Chưa hứa throughput/VRAM production |
| Giờ-người tiết kiệm mỗi finding | **Chưa đo** → business case **không** được nêu như số |

---

## 9. Nguồn kiểm chứng

- **Số tự đo:** `docs/plans/reports/2026-07-26-week12-measured-evidence-sheet.md` (180 dòng,
  dẫn tới file nguồn từng con số), `docs/ai-sast-research-log.md` (E1–E13),
  `docs/decisions/0017–0025`, `agent/finops.py`, các baseline JSON đã commit.
- **Số thị trường (có ghi độ tin cậy):**
  `docs/plans/reports/2026-07-26-week12-pentest-market-economics.md`.
- **Đo lại lớp AI (E13):** 4 lần chạy live (1 tất định + 3 có LLM) qua cổng, cùng target,
  ghi bằng FinOps — reproducible bằng `python -m agent.supervisor`.

---

## 10. Câu hỏi còn mở (cho mentor/lãnh đạo)

1. Có nên lấy **báo giá pentest địa phương (VN)** để thay dải $5k–50k bằng số chốt không?
2. Bước tiếp theo ưu tiên **đo giờ-người tiết kiệm/finding** (số ROI còn thiếu), hay
   **mở khóa probe đổi-trạng-thái** qua HITL để chạm lớp absence thật?
3. Bản bàn giao này có cần một target **thứ hai** (không phải Juice Shop model đã thuộc
   lòng) để chứng minh khái quát hóa trước khi trình lãnh đạo không?
