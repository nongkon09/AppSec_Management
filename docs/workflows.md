# Workflows — ขั้นตอนการทำงาน

เอกสารนี้อธิบายขั้นตอนการทำงานของแต่ละบทบาท รายละเอียดการออกแบบและเหตุผลอยู่ใน
[risk-exception-design.md](risk-exception-design.md)

## บทบาทที่เกี่ยวข้อง

| บทบาท | ในระบบ | หน้าที่ |
|---|---|---|
| ทีมพัฒนา / Tech Lead | `dev_team` | Maker — ยื่นคำขอยกเว้นสำหรับแอปของทีม, เขียนแผนแก้ไข |
| DevOps | `dev_team` หรือ `appsec` | ตรวจเลข EXC ก่อนปล่อยผ่าน, บันทึกการปล่อยผ่าน, บันทึก deployment |
| Pipeline | `pipeline` (บัญชีเครื่อง) | ส่ง SBOM เข้า DT, บันทึก deployment ผ่าน API |
| AppSec analyst | `appsec` + ระดับ `l1` | Checker ระดับต้น, Maker ได้, จัดการ Control Library |
| AppSec lead | `appsec` + ระดับ `l2` | Checker ระดับ High/Critical |
| CISO / ผู้บริหารความเสี่ยง | `management` หรือ `appsec` + ระดับ `l3` | Checker คนที่สองสำหรับ Critical/KEV/หลายแอป |
| Admin | `admin` | จัดการผู้ใช้และระดับการอนุมัติ — **อนุมัติความเสี่ยงไม่ได้** |
| Auditor | `audit` | ดูข้อมูลและ export Evidence Pack |

---

## W1. จากการสแกนถึงระบบ (ทุกเครื่องมือ)

```mermaid
sequenceDiagram
  autonumber
  participant Tool as เครื่องมือต้นทาง<br/>(RHACS / Harbor / Inspector / Syft)
  participant P as Pipeline
  participant DT as Dependency-Track
  participant A as AppSec Platform
  Tool->>P: SBOM (CycloneDX / SPDX)
  P->>DT: PUT /api/v1/bom<br/>projectName, projectVersion, projectTags
  DT->>DT: วิเคราะห์ช่องโหว่ (OSV / NVD)
  A->>DT: Sync (ทุก 6 ชม. หรือกด "Sync ทันที")
  DT-->>A: components + findings + tags + lastBomImport
  A->>A: สร้าง/อัปเดต finding, issue key, วันเริ่มนับ SLA
  A->>A: ใช้ Exception ที่อนุมัติแล้วกับ finding ใหม่ที่ key ตรงกัน
  A->>A: บันทึก Scan Snapshot ถ้า SBOM ใหม่
```

**สิ่งที่ pipeline ต้องส่ง** (ตัวอย่างที่ทดสอบกับ DT 4.14 แล้ว):

```bash
BOM_B64=$(base64 < sbom.cdx.json | tr -d '\n')
curl -X PUT "$DT_URL/api/v1/bom" \
  -H "X-Api-Key: $DT_UPLOAD_KEY" -H "Content-Type: application/json" \
  -d @- <<EOF
{
  "projectName": "$APP_NAME",
  "projectVersion": "$APP_VERSION",
  "autoCreate": true,
  "projectTags": [
    {"name": "commit:$GIT_COMMIT"},
    {"name": "digest:$(echo $IMAGE_DIGEST | tr ':' '-')"},
    {"name": "tool:$SCAN_TOOL"},
    {"name": "pipeline:$PIPELINE_RUN_ID"}
  ],
  "bom": "$BOM_B64"
}
EOF
```

- `projectName` ต้องตรงกับชื่อแอปในระบบ (ถ้ายังไม่มี ระบบสร้างให้และตั้งทีมเป็น `Unassigned` รอ AppSec ยืนยัน)
- `projectVersion` ใช้เวอร์ชัน release ไม่ใช่ `latest`

---

## W2. บันทึก Deployment (เวอร์ชันที่ใช้งานจริง)

```mermaid
flowchart TD
  D1[Pipeline ขั้น deploy สำเร็จ] --> D2{เรียก API ได้?}
  D2 -- ได้ --> D3[POST /api/v1/deployments<br/>app, version, environment, digest, pipeline url]
  D2 -- ไม่ได้ / deploy ด้วยมือ --> D4[DevOps บันทึกในหน้าแอปพลิเคชัน]
  D3 --> D5[ระบบปิด deployment เดิมใน environment เดียวกัน]
  D4 --> D5
  D5 --> D6[คำนวณเวอร์ชัน active ใหม่<br/>Backlog นับเฉพาะเวอร์ชัน active]
```

ตัวอย่างสำหรับ pipeline:

```bash
TOKEN=$(curl -s -X POST "$APPSEC_URL/api/v1/auth/login" \
  -d "username=$PIPELINE_USER&password=$PIPELINE_PASSWORD" | jq -r .access_token)
curl -X POST "$APPSEC_URL/api/v1/deployments" -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"application_name\":\"$APP_NAME\",\"version_label\":\"$APP_VERSION\",
       \"environment\":\"production\",\"image_digest\":\"$IMAGE_DIGEST\",
       \"reference_url\":\"$PIPELINE_URL\"}"
```

---

## W3. ถูกบล็อกที่เครื่องมือต้นทาง → ขอยกเว้น → ปล่อยผ่าน

```mermaid
sequenceDiagram
  autonumber
  actor Dev as ทีมพัฒนา (Maker)
  participant A as AppSec Platform
  actor C1 as ผู้อนุมัติคนที่ 1
  actor C2 as ผู้อนุมัติคนที่ 2<br/>(เฉพาะ Critical / KEV / หลายแอป)
  actor Ops as DevOps
  participant Tool as เครื่องมือต้นทาง
  Tool-->>Dev: Pipeline ถูกบล็อก (CVE-xxxx)
  Dev->>A: เปิดช่องโหว่ → "ขอยกเว้น"<br/>ประเภท, เหตุผล, control, residual severity, วันหมดอายุ
  A->>A: ตรวจกฎ (residual, KEV, วันหมดอายุ ≤ SLA<br/>หรือ ≤ วันนี้ + SLA 1 รอบ ถ้าเกินกำหนดแล้ว)<br/>คำนวณจำนวน/ระดับผู้อนุมัติ, ออกเลข EXC-2026-0001
  A-->>C1: แสดงใน "รอฉันอนุมัติ"
  C1->>A: อนุมัติ + ความเห็น
  opt ต้องอนุมัติ 2 คน
    A-->>C2: แสดงใน "รอฉันอนุมัติ"
    C2->>A: อนุมัติ + ความเห็น
  end
  A->>A: สถานะ approved<br/>finding → risk_accepted / suppressed<br/>ใช้ residual severity + SLA ใหม่
  Dev->>Ops: ขอปล่อยผ่าน พร้อมเลข EXC-2026-0001
  Ops->>A: ค้นเลข EXC ตรวจสถานะ ขอบเขต วันหมดอายุ
  Ops->>Tool: ปล่อยผ่านด้วยมือ
  Ops->>A: บันทึกการปล่อยผ่าน (เครื่องมือ, ลิงก์ pipeline, หมายเหตุ)
```

### จุดตรวจของ DevOps ก่อนปล่อยผ่าน

1. สถานะต้องเป็น **approved** เท่านั้น (pending / rejected / expired ห้ามปล่อย)
2. ช่องโหว่ที่ถูกบล็อกต้องอยู่ในขอบเขตของคำขอ (แอปเดียวกัน, CVE / component เดียวกัน)
3. ยังไม่เลยวันหมดอายุ
4. บันทึกการปล่อยผ่านกลับเข้าระบบทุกครั้ง

### ผู้อนุมัติต้องดูอะไร

- เหตุผลและหลักฐานเพียงพอหรือไม่
- control ที่อ้างถึงมีอยู่จริงและยังไม่เลยวันทบทวน
- Residual severity สมเหตุสมผลกับ control
- วันหมดอายุสั้นที่สุดเท่าที่จำเป็น
- ปฏิเสธได้พร้อมเหตุผล — ผู้ยื่นต้องยื่นใหม่

---

## W4. False Positive / Not Affected

```mermaid
flowchart TD
  F1[AppSec หรือทีมพัฒนาพบว่าเป็น false positive] --> F2[ยื่น Exception ประเภท false_positive หรือ not_affected<br/>เลือก VEX justification + หลักฐาน + วันทบทวน]
  F2 --> F3{Critical / KEV / หลายแอป?}
  F3 -- ไม่ใช่ --> F4[อนุมัติ 1 คน ระดับ ≥ L1]
  F3 -- Critical/KEV --> F5[อนุมัติ 1 คน ระดับ ≥ L2]
  F3 -- หลายแอป --> F6[อนุมัติ 2 คน ≥ L2 และ L3]
  F4 --> F7[finding → suppressed, VEX = not_affected]
  F5 --> F7
  F6 --> F7
  F7 --> F8[เวอร์ชันใหม่ที่เจอ key เดียวกันถูก suppress อัตโนมัติ]
  F8 --> F9[ถึงวันทบทวน → กลับเป็น open ต้องยื่นใหม่ถ้ายังเป็น false positive]
```

VEX justification ที่ใช้ได้ (มาตรฐาน CycloneDX / OpenVEX):
`code_not_present`, `code_not_reachable`, `requires_configuration`, `requires_dependency`,
`requires_environment`, `protected_by_compiler`, `protected_at_runtime`, `protected_at_perimeter`,
`protected_by_mitigating_control`

---

## W5. การคำนวณ SLA

```mermaid
flowchart TD
  S1[พบช่องโหว่ในเวอร์ชันใหม่] --> S2{มี finding key เดียวกันในแอปนี้<br/>ที่ยังไม่ถูกแก้?}
  S2 -- มี --> S3[ใช้วันเริ่มนับเดิมที่เก่าที่สุด]
  S2 -- ไม่มี --> S4[วันเริ่มนับ = วันนี้]
  S3 --> S5{มี Exception approved<br/>ที่ระบุ residual severity?}
  S4 --> S5
  S5 -- มี --> S6[วันครบกำหนด = วันเริ่มนับ + SLA ของ residual]
  S5 -- ไม่มี --> S7[วันครบกำหนด = วันเริ่มนับ + SLA ของ original]
```

ตัวอย่าง: พบ log4j (Critical, SLA 3 วัน) วันที่ 1 ต.ค. → ครบกำหนด 4 ต.ค.
ยื่นยกเว้นด้วย WAF + ไม่เปิดสู่อินเทอร์เน็ต ประเมิน residual เป็น High (SLA 30 วัน) และอนุมัติวันที่ 3 ต.ค.
→ ครบกำหนดใหม่ 31 ต.ค. (นับจาก 1 ต.ค. ไม่ใช่วันที่อนุมัติ) วันหมดอายุของ exception ต้องไม่เกิน 31 ต.ค.

**ช่องโหว่ที่เกิน SLA แล้ว** ต้องขอยกเว้นเท่านั้น

- แผนการแก้ไขยังบันทึกได้ และตั้งวันแก้เสร็จเป็นวันไหนก็ได้ ใช้แนบประกอบคำขอ แต่แผนไม่เปลี่ยนวันครบกำหนดหรือสถานะเกินกำหนด และไม่ปลดการบล็อก Go-Live
- หน้าช่องโหว่ขึ้นคำเตือนให้ไปยื่นขอยกเว้น
- วันหมดอายุของ exception ตั้งได้ไม่เกิน วันนี้ + SLA 1 รอบของ Residual Severity
  ตัวอย่าง: log4j เกินกำหนดมา 57 วัน ขอ residual High (SLA 30 วัน) วันที่ 28 ก.ย. → หมดอายุได้ไม่เกิน 28 ต.ค.
- ถ้าแผนแก้เสร็จช้ากว่าวันหมดอายุของ exception ต้องยื่นต่ออายุก่อนหมด ไม่เช่นนั้นช่องโหว่กลับเป็นเกินกำหนดทันที

---

## W6. หมดอายุ / เพิกถอน / ปิด

```mermaid
flowchart TD
  E1[งานรายวันของระบบ] --> E2{Exception approved<br/>ถึงวันหมดอายุ?}
  E2 -- ใช่ --> E3[สถานะ expired<br/>finding กลับเป็น open<br/>ใช้ original severity และ due date เดิม]
  E1 --> E4{control ที่ใช้เลยวันทบทวน?}
  E4 -- ใช่ --> E5[ทำเครื่องหมาย 'ต้องทบทวน' ที่ exception]
  E1 --> E6{finding ที่ครอบคลุมถูกแก้หมดแล้ว?}
  E6 -- ใช่ --> E7[สถานะ closed]
  R1[AppSec พบว่า control ใช้ไม่ได้แล้ว] --> R2[เพิกถอน + เหตุผล] --> E3
```

---

## W7. ตอบ Audit: เวอร์ชันที่ใช้งานกับผลสแกน

```mermaid
flowchart LR
  Q[Auditor: วันที่ X ระบบ Y ใช้เวอร์ชันอะไร<br/>และปล่อยช่องโหว่ไหนผ่าน ใครอนุมัติ] --> E[เปิดแอป Y → Export Evidence<br/>เลือกช่วงวันที่]
  E --> R1[Deployment ในช่วงนั้น: เวอร์ชัน, digest, commit, environment]
  E --> R2[Scan snapshot: เวลา, เครื่องมือ, SHA-256 ของ SBOM, ช่องโหว่ที่เจอ]
  E --> R3[Exception ที่ครอบคลุม: ผู้ยื่น, ผู้อนุมัติ, ความเห็น, วันหมดอายุ]
  E --> R4[การปล่อยผ่านของ DevOps: เวลา, เครื่องมือ, ลิงก์ pipeline]
```

---

## RACI สรุป

| กิจกรรม | ทีมพัฒนา | DevOps | Pipeline | AppSec L1 | AppSec L2 | CISO L3 | Admin | Audit |
|---|---|---|---|---|---|---|---|---|
| ส่ง SBOM เข้า DT | I | A | R | I | | | | |
| บันทึก deployment | | R/A | R | I | | | | I |
| ยื่นคำขอยกเว้น | R | | | R | C | | | |
| อนุมัติ Low/Medium | I | | | R/A | | | | I |
| อนุมัติ High | I | | | C | R/A | | | I |
| อนุมัติ Critical/KEV/หลายแอป | I | | | C | R | R/A | | I |
| ปล่อยผ่านที่เครื่องมือต้นทาง | I | R/A | | I | | | | I |
| จัดการ Control Library | | | | R | A | I | | I |
| กำหนดระดับผู้อนุมัติ | | | | | C | A | R | I |
| Export Evidence | | | | R | | | | R |

R = ลงมือทำ, A = รับผิดชอบผลลัพธ์, C = ให้คำปรึกษา, I = รับทราบ
