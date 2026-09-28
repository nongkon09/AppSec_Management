// English is the page's own text; Thai replaces it by data-i18n key.
const TH = {
  'nav.features': 'ความสามารถ',
  'nav.screenshots': 'ภาพหน้าจอ',
  'nav.start': 'เริ่มใช้งาน',
  'nav.docs': 'เอกสาร',
  'hero.eyebrow': 'Open source · ติดตั้งเองได้ · Apache-2.0',
  'hero.title': 'รู้ความเสี่ยงของทุกแอป ใครกำลังแก้ และต้องเสร็จเมื่อไหร่',
  'hero.lead':
    'รวมทะเบียนแอปพลิเคชัน ช่องโหว่ของ open source จาก SBOM การติดตาม SLA การขอยกเว้นความเสี่ยงแบบ maker–checker และหลักฐานที่ผู้ตรวจสอบต้องการ ไว้ในที่เดียว',
  'hero.start': 'เริ่มใช้งาน',
  'hero.github': 'ดูบน GitHub',
  'stats.sbom': 'CycloneDX และ SPDX, sync กับ Dependency-Track',
  'stats.intel': 'สัญญาณการถูกโจมตีจริงในทุกช่องโหว่',
  'stats.approvals': 'ระดับผู้อนุมัติแบบ maker–checker',
  'stats.lang': 'หน้าจอภาษาไทยและอังกฤษ',
  'features.title': 'ทำอะไรได้บ้าง',
  'features.lead': 'ออกแบบสำหรับทีม AppSec นักพัฒนา ผู้บริหาร และผู้ตรวจสอบ แต่ละบทบาทเห็นเฉพาะสิ่งที่ต้องใช้',
  'f.sbom.t': 'ทะเบียน SBOM',
  'f.sbom.d':
    'ดึงโปรเจกต์ component และช่องโหว่จาก OWASP Dependency-Track เติมข้อมูล CISA KEV, FIRST EPSS และ OSV ให้ และอัปโหลด SBOM ของ vendor เองได้',
  'f.sla.t': 'SLA ต่อปัญหา ไม่ใช่ต่อ build',
  'f.sla.d': 'เริ่มนับตั้งแต่พบช่องโหว่ในแอปครั้งแรก และนับต่อข้ามทุกเวอร์ชัน build ใหม่จึงไม่ได้เวลาเพิ่ม',
  'f.exc.t': 'ขอยกเว้นความเสี่ยงแบบ maker–checker',
  'f.exc.d':
    'ยอมรับความเสี่ยง, false positive และ not affected มีเลขอ้างอิง อนุมัติตามความรุนแรง (L1–L3) ความรุนแรงหลังมาตรการอ้างอิงคลังมาตรการควบคุม และมีวันหมดอายุ',
  'f.evidence.t': 'หลักฐานพร้อมตรวจ',
  'f.evidence.d':
    'เวอร์ชันไหนรันที่ไหนเมื่อไหร่ ผลสแกนและ hash ของ SBOM ใครอนุมัติข้อยกเว้น และการปล่อยผ่านที่เครื่องมือต้นทาง ส่งออกได้ในไฟล์เดียว',
  'f.policy.t': 'นโยบาย Severity และ SLA มีเวอร์ชัน',
  'f.policy.d': 'กำหนดระดับจาก CVSS, EPSS และ KEV นโยบายแต่ละเวอร์ชันมีวันเริ่มใช้และแก้ย้อนหลังไม่ได้ จึงตรวจย้อนได้ทุกการตัดสินใจ',
  'f.report.t': 'รายงานผู้บริหารรายเดือน',
  'f.report.d': 'ค้าง พบใหม่ แก้แล้ว แก้ทันกำหนด ความเสี่ยงที่ต้องจับตา และข้อยกเว้น ทั้งองค์กรหรือรายทีม พิมพ์หรือบันทึก PDF ได้',
  'f.entra.t': 'Microsoft Entra ID',
  'f.entra.d': 'เข้าสู่ระบบด้วย Microsoft (OIDC + PKCE), สร้างบัญชีผ่าน SCIM และได้บทบาทจากกลุ่มหรือ app role มีบัญชีผู้ดูแลสำรองไว้เสมอ',
  'f.more.t': 'Pentest, ITSM และอื่น ๆ',
  'f.more.d': 'จัดการโครงการ Pentest และค่าใช้จ่าย, ส่ง ticket เข้า Jira ตามความรุนแรง, checklist ก่อนขึ้นระบบ, Audit Trail แบบแก้ไม่ได้, ธีมสว่างและมืด',
  'shots.title': 'ตัวอย่างหน้าจอ',
  'shots.lead': 'หน้าจอจริงจากข้อมูลตัวอย่าง ตอนนี้แสดงหน้าจอภาษาไทย',
  'flow.title': 'ทำงานกับ pipeline ของคุณอย่างไร',
  'flow.1t': 'CI build และสแกน',
  'flow.1d': 'pipeline ส่ง SBOM เข้า Dependency-Track และบันทึกการ deploy',
  'flow.2t': 'ระบบ sync ข้อมูล',
  'flow.2d': 'จัดระดับความรุนแรงตามนโยบาย รวมเป็นรายปัญหา และกำหนด SLA',
  'flow.3t': 'ทีมลงมือ',
  'flow.3d': 'นักพัฒนาวางแผนแก้หรือขอยกเว้น AppSec และผู้บริหารอนุมัติ',
  'flow.4t': 'พิสูจน์ได้ทุกเมื่อ',
  'flow.4d': 'รายงานให้ผู้บริหาร หลักฐานให้ผู้ตรวจสอบ จากข้อมูลชุดเดียวกัน',
  'start.title': 'เริ่มใช้งาน',
  'start.lead': 'ต้องมี Docker ชุดสำหรับพัฒนามี Dependency-Track และข้อมูลตัวอย่างให้',
  'start.c1': 'เปิด http://localhost:5173 แล้วเข้าด้วย appsec.lead / ChangeMe123!',
  'start.c2': 'Production: สคริปต์เดียวติดตั้งทั้งระบบและ Dependency-Track พร้อมสุ่มรหัสลับทั้งหมด',
  'start.c3': 'เครื่องที่ไม่มี internet: สร้าง offline bundle ที่รวม image ทั้งหมด',
  'start.guide': 'คู่มือติดตั้ง',
  'start.dev': 'สำหรับพัฒนา',
  'start.prod': 'Production (เครื่องเดียว)',
  copy: 'คัดลอก',
  'stack.title': 'สร้างด้วย',
  'cta.title': 'ใช้ แก้ไข และติดตั้งเองได้ฟรี',
  'cta.lead': 'ใช้สัญญาอนุญาต Apache-2.0 ยินดีรับ issue และ pull request',
  'cta.star': 'กดดาวบน GitHub',
  'cta.issue': 'แจ้งปัญหา',
  'footer.workflows': 'ขั้นตอนการทำงาน',
  'footer.changelog': 'บันทึกการเปลี่ยนแปลง',
  'footer.license': 'สัญญาอนุญาต',
}

const SHOTS = [
  {
    id: 'findings',
    en: ['Vulnerabilities', 'One backlog across applications and scan types, filtered by severity, SLA state, team and exploitation signals.'],
    th: ['ช่องโหว่', 'รายการเดียวครอบคลุมทุกแอปและทุกประเภทการสแกน กรองตามความรุนแรง สถานะ SLA ทีม และสัญญาณการถูกโจมตี'],
  },
  {
    id: 'finding',
    en: ['Vulnerability detail', 'A guided remediation plan with SLA warnings. Once past the SLA, the page says an exception is required.'],
    th: ['รายละเอียดช่องโหว่', 'แผนการแก้ไขแบบกดเลือก พร้อมเตือนเรื่อง SLA ถ้าเกินกำหนดแล้ว หน้าจอบอกให้ขอยกเว้น'],
  },
  {
    id: 'exception',
    en: ['Risk exception', 'Original and residual severity, controls cited, required approvers, and every decision with its comment.'],
    th: ['ข้อยกเว้น', 'ความรุนแรงเดิมและหลังมาตรการ มาตรการที่อ้างอิง ผู้อนุมัติที่ต้องมี และทุกการตัดสินใจพร้อมความเห็น'],
  },
  {
    id: 'exceptions',
    en: ['Exception register', 'What is waiting for me, what is in force and what expires soon, with reference numbers DevOps can check.'],
    th: ['ทะเบียนข้อยกเว้น', 'รายการที่รอฉันอนุมัติ ที่มีผลอยู่ และที่ใกล้หมดอายุ พร้อมเลขอ้างอิงให้ DevOps ตรวจ'],
  },
  {
    id: 'application',
    en: ['Application', 'Where each version runs, recorded by the pipeline, and one-click evidence export for auditors.'],
    th: ['แอปพลิเคชัน', 'เวอร์ชันไหนรันที่ไหน บันทึกโดย pipeline และส่งออกหลักฐานให้ผู้ตรวจสอบได้ในคลิกเดียว'],
  },
  {
    id: 'report',
    en: ['Executive summary', 'Monthly figures for leadership with trends, top risks and exceptions. Print or save as PDF.'],
    th: ['รายงานผู้บริหาร', 'ตัวเลขรายเดือนพร้อมแนวโน้ม ความเสี่ยงที่ต้องจับตา และข้อยกเว้น พิมพ์หรือบันทึก PDF ได้'],
  },
  {
    id: 'sbom',
    en: ['SBOM', 'Sync from Dependency-Track or upload a vendor SBOM; see what came in and which versions are out of date.'],
    th: ['SBOM', 'sync จาก Dependency-Track หรืออัปโหลด SBOM ของ vendor ดูว่ามีอะไรเข้ามาและเวอร์ชันไหนไม่ได้อัปเดต'],
  },
  {
    id: 'policy',
    en: ['Policy', 'Severity rules and SLA days as versioned, effective-dated policy with a readable history.'],
    th: ['นโยบาย', 'กฎความรุนแรงและจำนวนวัน SLA แบบมีเวอร์ชันและวันเริ่มใช้ พร้อมประวัติที่อ่านง่าย'],
  },
  {
    id: 'entra',
    en: ['Entra ID', 'Connection status, the URLs to register, and which Entra group or app role gets which role.'],
    th: ['Entra ID', 'สถานะการเชื่อมต่อ URL ที่ต้องลงทะเบียน และกลุ่มหรือ app role ไหนได้บทบาทอะไร'],
  },
]

const english = new Map()
document.querySelectorAll('[data-i18n]').forEach((el) => english.set(el, el.textContent))

let lang = 'en'
let current = SHOTS[0].id

function readLang() {
  try {
    const saved = localStorage.getItem('site.lang')
    if (saved === 'en' || saved === 'th') return saved
  } catch {
    // Storage blocked: fall back to the browser language.
  }
  return (navigator.language || '').toLowerCase().startsWith('th') ? 'th' : 'en'
}

function showShot(id) {
  current = id
  const shot = SHOTS.find((item) => item.id === id)
  const [title, caption] = shot[lang]
  const image = document.getElementById('shot-image')
  image.src = `screenshots/${id}-${lang}.webp`
  image.alt = `${title}: ${caption}`
  document.getElementById('shot-caption').textContent = caption
  document.querySelectorAll('.tab').forEach((tab) => {
    const selected = tab.dataset.id === id
    tab.setAttribute('aria-selected', String(selected))
    tab.tabIndex = selected ? 0 : -1
  })
}

function buildTabs() {
  const list = document.getElementById('shot-tabs')
  list.replaceChildren(
    ...SHOTS.map((shot) => {
      const tab = document.createElement('button')
      tab.type = 'button'
      tab.className = 'tab'
      tab.role = 'tab'
      tab.dataset.id = shot.id
      tab.textContent = shot[lang][0]
      tab.setAttribute('aria-controls', 'shot-image')
      tab.addEventListener('click', () => showShot(shot.id))
      return tab
    }),
  )
  list.onkeydown = (event) => {
    if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return
    const index = SHOTS.findIndex((shot) => shot.id === current)
    const next = SHOTS[(index + (event.key === 'ArrowRight' ? 1 : SHOTS.length - 1)) % SHOTS.length]
    showShot(next.id)
    list.querySelector(`[data-id="${next.id}"]`).focus()
  }
  showShot(current)
}

function applyLang(next) {
  lang = next
  document.documentElement.lang = lang
  english.forEach((text, el) => {
    const key = el.dataset.i18n
    el.textContent = lang === 'th' && TH[key] ? TH[key] : text
  })
  document.querySelectorAll('[data-shot]').forEach((img) => {
    img.src = `screenshots/${img.dataset.shot}-${lang}.webp`
  })
  const toggle = document.getElementById('lang-toggle')
  toggle.textContent = lang === 'th' ? 'English' : 'ไทย'
  toggle.setAttribute('aria-label', lang === 'th' ? 'Switch to English' : 'เปลี่ยนเป็นภาษาไทย')
  buildTabs()
}

document.getElementById('lang-toggle').addEventListener('click', () => {
  const next = lang === 'th' ? 'en' : 'th'
  try {
    localStorage.setItem('site.lang', next)
  } catch {
    // Not remembered; the switch still works for this visit.
  }
  applyLang(next)
})

document.querySelectorAll('.copy').forEach((button) => {
  button.addEventListener('click', async () => {
    const code = document.getElementById(`code-${button.dataset.copy}`).textContent
    try {
      await navigator.clipboard.writeText(code)
      const label = button.textContent
      button.textContent = lang === 'th' ? 'คัดลอกแล้ว' : 'Copied'
      setTimeout(() => (button.textContent = label), 1500)
    } catch {
      // Clipboard unavailable (insecure context); the text is still selectable.
    }
  })
})

applyLang(readLang())
