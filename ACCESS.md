# วิธีเข้าใช้งานระบบ (Local Development)

เอกสารนี้สรุปวิธีเข้าถึงทุกส่วนของระบบที่รันบนเครื่อง developer ด้วย `docker-compose.dev.yml`
ค่าทั้งหมดในนี้ใช้สำหรับ **dev เท่านั้น** ห้ามนำไปใช้กับ production

## 1. เปิด/ปิดระบบ

```bash
# เปิดทุก service
docker compose -f docker-compose.dev.yml up -d

# ปิดทุก service (ข้อมูลใน volume ยังอยู่)
docker compose -f docker-compose.dev.yml down

# ดู log ของ service ใด service หนึ่ง
docker compose -f docker-compose.dev.yml logs -f backend
```

ครั้งแรกหลังสร้างฐานข้อมูลใหม่ ให้สร้างผู้ใช้ตัวอย่างและข้อมูลตัวอย่าง:

```bash
docker compose -f docker-compose.dev.yml exec backend python -m app.seed --demo
```

## 2. URL ของแต่ละ service

| Service | URL | ใช้ทำอะไร |
| --- | --- | --- |
| AppSec Platform (หน้าเว็บ) | http://localhost:5173 | หน้าจอหลักสำหรับผู้ใช้ทุกบทบาท |
| Backend API | http://localhost:8000/api/v1 | REST API ของแพลตฟอร์ม |
| API Docs (Swagger) | http://localhost:8000/docs | ดู/ทดลองเรียก API |
| Health check | http://localhost:8000/health | ตรวจว่า backend ทำงานอยู่ |
| Dependency-Track UI | http://localhost:8082 | ดูโปรเจกต์/ช่องโหว่ฝั่ง DT |
| Dependency-Track API | http://localhost:8081 | API ที่ CI/CD และแพลตฟอร์มเรียกใช้ |
| Adminer (ดูฐานข้อมูล) | http://localhost:8083 | เปิดดูตารางใน PostgreSQL |
| PostgreSQL | localhost:5432 | เชื่อมต่อด้วย DB client |

## 3. บัญชีผู้ใช้ของแพลตฟอร์ม

ทุกบัญชีใช้รหัสผ่าน `ChangeMe123!` (สร้างจาก `python -m app.seed`)

| Username | บทบาท | ทีม | เห็นอะไรได้บ้าง |
| --- | --- | --- | --- |
| `appsec.lead` | ทีม AppSec / Security (**ผู้อนุมัติ L2**) | – | ทุกหน้ายกเว้นตั้งค่า อนุมัติข้อยกเว้นระดับ High (และเป็นคนแรกของ Critical), ยกเลิกข้อยกเว้น, จัดการคลังมาตรการควบคุม, อนุมัติ Go-Live, สร้าง Ticket |
| `appsec.analyst` | ทีม AppSec / Security (**ผู้อนุมัติ L1**) | – | เหมือน `appsec.lead` แต่อนุมัติข้อยกเว้นได้เฉพาะ Low/Medium และ FP/NA ที่ไม่ใช่ Critical/KEV |
| `dev.alpha` | ทีมพัฒนา / Tech Lead | Team Alpha | เฉพาะแอปของ Team Alpha: เขียนแผนการแก้ไข, **ขอยกเว้น** (Maker), บันทึก deploy, บันทึกการปล่อยผ่านที่เครื่องมือต้นทาง, ส่งออกหลักฐาน |
| `dev.beta` | ทีมพัฒนา / Tech Lead | Team Beta | เหมือน `dev.alpha` แต่เห็นเฉพาะแอปของ Team Beta |
| `mgmt.exec` | ผู้บริหาร / Product Owner (**ผู้อนุมัติ L3**) | – | ภาพรวม, ช่องโหว่, แอปพลิเคชัน, Pentest รวมรายงานค่าใช้จ่าย, อนุมัติข้อยกเว้นทุกระดับ (จำเป็นสำหรับ Critical/KEV และคำขอหลายแอป) |
| `audit.viewer` | Compliance / Audit | – | ดูอย่างเดียวทั้งหมด รวมข้อยกเว้น, คลังมาตรการ, Audit Trail และส่งออกหลักฐาน (Evidence Pack) |
| `legal.officer` | ฝ่ายกฎหมาย / Compliance | – | เฉพาะหน้าแอปพลิเคชัน (หน้าแรกจะขึ้นว่าไม่มีสิทธิ์ ให้กดเมนู "แอปพลิเคชัน") |
| `ci.pipeline` | บัญชีระบบสำหรับ CI/CD | – | **ไม่ได้ใช้ login หน้าเว็บ** เรียกได้แค่ `POST /deployments`, `GET /exceptions/by-reference/{เลข}` และ `GET /auth/me` |
| `sysadmin` | ผู้ดูแลระบบ | – | ทุกหน้า รวมถึงตั้งค่าผู้ใช้งาน (กำหนดระดับการอนุมัติ) และการเชื่อมต่อ (Jira/ITSM) **ไม่มีสิทธิ์อนุมัติข้อยกเว้น** |

> ข้อยกเว้นใช้หลัก Maker–Checker: ผู้ขออนุมัติคำขอของตัวเองไม่ได้ และหนึ่งคนนับได้ครั้งเดียว ขั้นตอนเต็มดูที่ [docs/workflows.md](docs/workflows.md) กฎและเหตุผลดูที่ [docs/risk-exception-design.md](docs/risk-exception-design.md)

สลับภาษา ไทย/English, โหมดมืด/สว่าง และออกจากระบบ ได้จากเมนูที่ชื่อผู้ใช้มุมขวาบน

> เข้าสู่ระบบด้วย Microsoft (Entra ID) ปิดอยู่ใน dev จนกว่าจะใส่ `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET` (และ `SCIM_BEARER_TOKEN` ถ้าจะลอง SCIM) ใน `.env` ที่ root แล้ว `docker compose -f docker-compose.dev.yml up -d backend` redirect URI สำหรับ dev คือ `http://localhost:8000/api/v1/auth/sso/callback` ขั้นตอนเต็มดูที่ [docs/entra-id.md](docs/entra-id.md)

### เรียก API โดยตรง

```bash
# ขอ token (endpoint รับเป็น form data ไม่ใช่ JSON)
TOKEN=$(curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -d 'username=appsec.lead&password=ChangeMe123!' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

# ใช้ token เรียก API
curl -s http://localhost:8000/api/v1/findings/summary -H "Authorization: Bearer $TOKEN"
```

## 4. Dependency-Track

### ตั้งค่าครั้งแรก

```bash
# รอจน http://localhost:8081/api/version ตอบกลับ แล้วรัน:
python3 deploy/production/scripts/dtrack-bootstrap.py --url http://localhost:8081 --env-file .env
docker compose -f docker-compose.dev.yml up -d backend              # ให้ backend อ่าน key ใหม่
docker compose -f docker-compose.dev.yml restart dtrack-apiserver   # เริ่มดาวน์โหลดข้อมูลช่องโหว่ OSV
```

สคริปต์รันซ้ำได้ ไม่สร้างของซ้ำ (สคริปต์เดียวกับที่ใช้ติดตั้ง production — ดู [docs/deployment-guide.md](docs/deployment-guide.md))

### บัญชีและ key

ข้อมูลลับทั้งหมดอยู่ในไฟล์ `.env` ที่ root ของ repo (ไฟล์นี้อยู่ใน `.gitignore` ห้าม commit)

| ค่าใน `.env` | ใช้ทำอะไร |
| --- | --- |
| `DTRACK_ADMIN_PASSWORD` | รหัสผ่านของผู้ใช้ `admin` สำหรับ login หน้า Dependency-Track UI |
| `DEPENDENCY_TRACK_API_KEY` | key อ่านอย่างเดียว ให้แพลตฟอร์มใช้ sync (ทีม "AppSec Platform - Sync (read-only)") |
| `DEPENDENCY_TRACK_UPLOAD_API_KEY` | key สำหรับส่ง SBOM เข้า DT ใช้ทั้งกับการอัปโหลดผ่านแพลตฟอร์มและ CI/CD (ทีม "AppSec Platform - SBOM Upload") |

ดูค่าได้ด้วย `cat .env` (อย่าแชร์ค่าเหล่านี้ในแชทหรือ ticket)

### ส่ง SBOM เข้า DT แบบ CI/CD

สร้าง SBOM ด้วย Syft (ผ่าน Docker ไม่ต้องติดตั้ง) ในรูปแบบ CycloneDX JSON 1.6:

```bash
docker run --rm -v "$PWD":/src anchore/syft:latest scan dir:/src \
  --source-name "My App" --source-version 1.0.0 \
  -o cyclonedx-json@1.6=/src/sbom.cdx.json
```

ส่งเข้า DT (สร้างโปรเจกต์ให้อัตโนมัติถ้ายังไม่มี):

```bash
set -a; . ./.env; set +a
curl -X POST http://localhost:8081/api/v1/bom \
  -H "X-Api-Key: $DEPENDENCY_TRACK_UPLOAD_API_KEY" \
  -F "projectName=My App" -F "projectVersion=1.0.0" -F "autoCreate=true" \
  -F "bom=@sbom.cdx.json"
```

### ดึงข้อมูลจาก DT เข้าแพลตฟอร์ม

- ผ่านหน้าเว็บ: login ด้วย `appsec.lead` หรือ `sysadmin` → เมนู **SBOM** → กด **Sync ทันที**
- ผ่าน API: `curl -X POST http://localhost:8000/api/v1/sbom/sync -H "Authorization: Bearer $TOKEN"`
- อัตโนมัติ: ใส่ `ENABLE_SCHEDULER=true` ใน `.env` แล้วรัน `docker compose -f docker-compose.dev.yml up -d backend` (sync ทุก 6 ชั่วโมง)

แอปที่มาจาก DT แต่ยังไม่มีในแพลตฟอร์มจะถูกสร้างให้อัตโนมัติ โดยทีมเจ้าของเป็น `Unassigned` รอทีม AppSec ยืนยัน

## 5. ฐานข้อมูล

เปิด Adminer ที่ http://localhost:8083 แล้วกรอก:

| ช่อง | ค่า |
| --- | --- |
| System | PostgreSQL |
| Server | `postgres` |
| Username | `appsec` |
| Password | `appsec` |
| Database | `appsec` (แพลตฟอร์ม) หรือ `dtrack` (Dependency-Track) |

ถ้าใช้ DB client จากเครื่อง ให้ต่อที่ `localhost:5432` ด้วย user/password เดียวกัน

## 6. ปัญหาที่พบบ่อย

| อาการ | วิธีแก้ |
| --- | --- |
| หน้าเว็บขึ้น error หา package ไม่เจอ หลัง pull โค้ดใหม่ | `docker compose -f docker-compose.dev.yml exec frontend npm install` แล้ว `restart frontend` |
| backend error เรื่อง migration | `docker compose -f docker-compose.dev.yml exec backend alembic upgrade head` |
| Login แล้วเห็นหน้า "ไม่มีสิทธิ์" | บทบาทนั้นเปิดหน้านั้นไม่ได้ ดูตารางข้อ 3 หรือออกจากระบบแล้วเข้าด้วยบัญชีอื่น |
| Sync แล้วไม่มีช่องโหว่ใหม่ | DT อาจยังวิเคราะห์ไม่เสร็จ หรือยังดาวน์โหลดข้อมูลช่องโหว่ไม่ครบ ดู log: `docker compose -f docker-compose.dev.yml logs dtrack-apiserver` |
| Sync ครั้งแรกช้า (หลายสิบวินาที) | ปกติ ระบบต้องค้นหา CVE ของ advisory ใหม่ผ่าน OSV.dev ครั้งถัดไปจะเร็ว |
