/**
 * PDF to Firestore — Two-Phase Approach
 * 
 * Phase 1: OCR the scanned PDF once using Gemini Flash (cheap, fast)
 *          Save raw text to a local cache file
 * Phase 2: Parse the raw text into structured JSON using Flash on plain text
 *          Upload to Firestore
 *
 * This sends the 393-page PDF only ONCE instead of 27+ times.
 * Estimated cost: ~$0.10-0.30 instead of ~$5-8
 *
 * Usage: npx tsx scripts/pdf-to-database.ts
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { GoogleGenerativeAI } from '@google/generative-ai';
import { GoogleAIFileManager } from '@google/generative-ai/server';
import { initializeApp, applicationDefault } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- ENV ---
const envPath = path.join(__dirname, '..', '.env.local');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf-8').split('\n').forEach(line => {
    const [key, ...val] = line.split('=');
    if (key && val.length) process.env[key.trim()] = val.join('=').trim();
  });
}

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) { console.error('❌ GEMINI_API_KEY not found'); process.exit(1); }

// --- FIREBASE ---
const PROJECT_ID = 'gen-lang-client-0658504679';
initializeApp({ credential: applicationDefault(), projectId: PROJECT_ID });
const db = getFirestore();

// --- GEMINI ---
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const fileManager = new GoogleAIFileManager(GEMINI_API_KEY);

// Flash for OCR (cheap) — Pro only if Flash fails
const FLASH_MODEL = 'gemini-3-flash-preview';

const VALID_DOMAINS = [
  'General Security Concepts',
  'Threats, Vulnerabilities, Mitigations',
  'Security Architecture',
  'Security Operations',
  'Governance, Risk, Compliance'
] as const;

// --- TYPES ---
interface ExtractedQuestion {
  questionNumber: number;
  examSection: string;
  question: string;
  options: string[];
  correctIndex: number;
  explanation: string;
  rationales: string[];
  objectiveCodes: string[];
  domain: string;
  tags: string[];
  threatLevel: string;
  logs: string[];
  page?: number;
}

// --- HELPERS ---
function normalizeDomain(raw: string): string {
  const lower = raw.toLowerCase();
  for (const d of VALID_DOMAINS) {
    if (lower.includes(d.toLowerCase().slice(0, 15))) return d;
  }
  if (lower.includes('threat') || lower.includes('vuln') || lower.includes('attack')) return 'Threats, Vulnerabilities, Mitigations';
  if (lower.includes('architect') || lower.includes('infra')) return 'Security Architecture';
  if (lower.includes('operation') || lower.includes('incident')) return 'Security Operations';
  if (lower.includes('govern') || lower.includes('risk') || lower.includes('compliance')) return 'Governance, Risk, Compliance';
  return 'General Security Concepts';
}

function normalizeThreatLevel(raw: string): string {
  const valid = ['low', 'medium', 'high', 'critical'];
  return valid.includes(raw?.toLowerCase()) ? raw.toLowerCase() : 'medium';
}

function generateId(examSection: string, questionNumber: number): string {
  const letter = examSection.replace(/Exam\s*/i, '').charAt(0).toUpperCase() || 'X';
  return `EXAM-${letter}-Q${String(questionNumber).padStart(2, '0')}`;
}

function toFirestoreDoc(q: ExtractedQuestion) {
  const id = generateId(q.examSection, q.questionNumber);
  return {
    id,
    domain: normalizeDomain(q.domain),
    question: q.question,
    options: q.options,
    correctIndex: q.correctIndex,
    explanation: q.explanation,
    rationales: q.rationales?.length === 4 ? q.rationales : [
      'CORRECT: See explanation.', 'INCORRECT: See explanation.',
      'INCORRECT: See explanation.', 'INCORRECT: See explanation.'
    ],
    objectiveCodes: q.objectiveCodes || [],
    tags: q.tags?.length ? q.tags : ['Security Concepts'],
    threatLevel: normalizeThreatLevel(q.threatLevel),
    logs: q.logs?.length ? q.logs : ['SYSTEM: Security event logged'],
    refs: [{ source: 'Practice Exams' as const, section: q.examSection, ...(q.page ? { page: q.page } : {}) }]
  };
}

function salvageJson(raw: string): ExtractedQuestion[] {
  const lastBrace = raw.lastIndexOf('}');
  if (lastBrace === -1) return [];
  let attempt = raw.slice(raw.indexOf('['), lastBrace + 1) + ']';
  try { return JSON.parse(attempt); } catch { return []; }
}

// ============================================================
// PHASE 1: OCR — Send the PDF once, get raw text back
// ============================================================
async function ocrPdf(fileUri: string, fileMimeType: string): Promise<string> {
  const cacheFile = path.join(__dirname, '..', '.ocr-cache.txt');

  // Use cache if it exists (skip re-uploading)
  if (fs.existsSync(cacheFile)) {
    const cached = fs.readFileSync(cacheFile, 'utf-8');
    if (cached.length > 5000) {
      console.log(`   📂 Using cached OCR (${(cached.length / 1024).toFixed(0)} KB)`);
      return cached;
    }
  }

  console.log('   🔍 Running OCR on full PDF (one-time cost)...');

  const model = genAI.getGenerativeModel({
    model: FLASH_MODEL,
    generationConfig: { maxOutputTokens: 65536, temperature: 0 },
  });

  // OCR in 3 chunks (one per exam) to stay within output limits
  const chunks = [
    { label: 'Exam A questions', pages: 'pages 7 through 44' },
    { label: 'Exam A answers', pages: 'pages 44 through 139' },
    { label: 'Exam B questions', pages: 'pages 140 through 170' },
    { label: 'Exam B answers', pages: 'pages 172 through 265' },
    { label: 'Exam C questions', pages: 'pages 266 through 298' },
    { label: 'Exam C answers', pages: 'pages 300 through 392' },
  ];

  let fullText = '';

  for (const chunk of chunks) {
    console.log(`      📖 OCR: ${chunk.label} (${chunk.pages})...`);

    const result = await model.generateContent([
      { fileData: { mimeType: fileMimeType, fileUri } },
      { text: `Transcribe ALL text from ${chunk.pages} of this scanned PDF exactly as written.
Include question numbers, all answer options (A/B/C/D), and all explanation text.
Preserve the structure: question number, question text, options, then for answers include the question number, correct answer letter, and full explanation.
Output plain text only, no JSON, no markdown formatting.
Be thorough — do not skip any questions or answers.` }
    ]);

    const text = result.response.text();
    console.log(`      ✅ Got ${text.length} chars`);
    fullText += `\n\n=== ${chunk.label.toUpperCase()} ===\n\n${text}`;

    await new Promise(r => setTimeout(r, 3000));
  }

  // Cache it
  fs.writeFileSync(cacheFile, fullText, 'utf-8');
  console.log(`   💾 Cached OCR to .ocr-cache.txt (${(fullText.length / 1024).toFixed(0)} KB)`);

  return fullText;
}

// ============================================================
// PHASE 2: Structure — Parse plain text into Scenario objects
// ============================================================
async function structureBatch(
  rawText: string,
  examLabel: string,
  startQ: number,
  endQ: number,
  retryCount = 0
): Promise<ExtractedQuestion[]> {
  const model = genAI.getGenerativeModel({
    model: FLASH_MODEL,
    generationConfig: { maxOutputTokens: 65536, temperature: 0.1 },
  });

  const prompt = `Below is OCR text from Professor Messer's SY0-701 Practice Exams PDF.
It contains questions and their answer explanations for "${examLabel}".

Extract questions ${startQ} through ${endQ} and return a JSON array:

[
  {
    "questionNumber": ${startQ},
    "examSection": "${examLabel}",
    "question": "Full question text",
    "options": ["A. text", "B. text", "C. text", "D. text"],
    "correctIndex": 0,
    "explanation": "Brief explanation (1-2 sentences)",
    "rationales": ["CORRECT: Why right.", "INCORRECT: Why wrong.", "INCORRECT: Why wrong.", "INCORRECT: Why wrong."],
    "objectiveCodes": ["1.2"],
    "domain": "General Security Concepts",
    "tags": ["Keyword1", "Keyword2"],
    "threatLevel": "medium",
    "logs": ["SIEM_ALERT: relevant log"],
    "page": 10
  }
]

RULES:
- JSON array ONLY. No markdown, no fences, no extra text.
- "domain" must be exactly: "General Security Concepts", "Threats, Vulnerabilities, Mitigations", "Security Architecture", "Security Operations", or "Governance, Risk, Compliance"
- "rationales": exactly 4, matching option order, prefixed CORRECT:/INCORRECT:
- "correctIndex": 0-based index of the correct option
- Match each question with its answer from the answers section
- Keep explanations concise

OCR TEXT:
${rawText}`;

  try {
    const result = await model.generateContent([{ text: prompt }]);
    const jsonStr = result.response.text().replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    console.log(`      📄 ${jsonStr.length} chars`);

    try {
      const q = JSON.parse(jsonStr);
      return Array.isArray(q) ? q : [];
    } catch {
      const salvaged = salvageJson(jsonStr);
      if (salvaged.length > 0) {
        console.log(`      🔧 Salvaged ${salvaged.length}`);
        return salvaged;
      }
      if (retryCount === 0 && endQ - startQ > 3) {
        const mid = Math.floor((startQ + endQ) / 2);
        console.log(`      🔄 Splitting Q${startQ}-${mid} + Q${mid+1}-${endQ}`);
        const a = await structureBatch(rawText, examLabel, startQ, mid, 1);
        await new Promise(r => setTimeout(r, 2000));
        const b = await structureBatch(rawText, examLabel, mid + 1, endQ, 1);
        return [...a, ...b];
      }
      return [];
    }
  } catch (error: any) {
    const msg = error.message || '';
    console.error(`   ⚠️ ${examLabel} Q${startQ}-${endQ}: ${msg.slice(0, 120)}`);
    if (retryCount === 0) {
      await new Promise(r => setTimeout(r, msg.includes('429') ? 30000 : 5000));
      return structureBatch(rawText, examLabel, startQ, endQ, 1);
    }
    return [];
  }
}

// --- FIRESTORE ---
async function uploadToFirestore(questions: ExtractedQuestion[]) {
  let total = 0;
  for (let i = 0; i < questions.length; i += 450) {
    const chunk = questions.slice(i, i + 450);
    const batch = db.batch();
    for (const q of chunk) {
      const data = toFirestoreDoc(q);
      batch.set(db.collection('scenarios').doc(data.id), data);
    }
    await batch.commit();
    total += chunk.length;
    console.log(`   🔥 Committed: ${total}/${questions.length}`);
  }
  return total;
}

// --- MAIN ---
async function main() {
  const pdfPath = path.join(__dirname, '..', 'SY0-701 Practice Exams.pdf');
  if (!fs.existsSync(pdfPath)) { console.error('❌ PDF not found:', pdfPath); process.exit(1); }

  const sizeMB = (fs.statSync(pdfPath).size / 1024 / 1024).toFixed(1);
  console.log(`📋 PDF: SY0-701 Practice Exams.pdf (${sizeMB} MB, 393 pages, scanned)`);
  console.log(`🧠 Strategy: OCR once with Flash → structure with Flash on text`);
  console.log(`💰 Estimated cost: ~$0.10-0.30 (vs ~$5-8 sending full PDF per batch)\n`);

  // 1. Upload PDF
  console.log('🚀 Uploading PDF...');
  const upload = await fileManager.uploadFile(pdfPath, {
    mimeType: 'application/pdf',
    displayName: 'SY0-701 Practice Exams',
  });
  console.log(`   ✅ ${upload.file.uri}`);

  // 2. Wait for processing
  console.log('   ⏳ Processing...');
  let file = await fileManager.getFile(upload.file.name);
  while (file.state === 'PROCESSING') {
    process.stdout.write('.');
    await new Promise(r => setTimeout(r, 3000));
    file = await fileManager.getFile(upload.file.name);
  }
  if (file.state === 'FAILED') { console.error('\n❌ Failed.'); process.exit(1); }
  console.log('\n   ✅ Ready.\n');

  // 3. Phase 1: OCR (sends PDF only once per chunk, cached after)
  console.log('═══ PHASE 1: OCR ═══');
  const ocrText = await ocrPdf(upload.file.uri, upload.file.mimeType);
  console.log(`   📊 Total OCR: ${(ocrText.length / 1024).toFixed(0)} KB\n`);

  // 4. Phase 2: Structure (text-only, no PDF sent)
  console.log('═══ PHASE 2: STRUCTURING ═══');
  const allQuestions: ExtractedQuestion[] = [];

  // Split OCR text by exam sections for context
  const examSections = [
    { label: 'Exam A', pattern: /=== EXAM A QUESTIONS ===([\s\S]*?)=== EXAM A ANSWERS ===([\s\S]*?)(?====|$)/i },
    { label: 'Exam B', pattern: /=== EXAM B QUESTIONS ===([\s\S]*?)=== EXAM B ANSWERS ===([\s\S]*?)(?====|$)/i },
    { label: 'Exam C', pattern: /=== EXAM C QUESTIONS ===([\s\S]*?)=== EXAM C ANSWERS ===([\s\S]*?)(?====|$)/i },
  ];

  for (const exam of examSections) {
    console.log(`\n🤖 ${exam.label}...`);

    const match = ocrText.match(exam.pattern);
    let examText: string;
    if (match) {
      examText = match[0];
      console.log(`   📝 Matched section: ${(examText.length / 1024).toFixed(0)} KB`);
    } else {
      // Fallback: send full text (less ideal but works)
      console.log(`   ⚠️ Couldn't isolate section, using full text`);
      examText = ocrText;
    }

    const BATCH = 10;
    for (let start = 1; start <= 90; start += BATCH) {
      const end = Math.min(start + BATCH - 1, 90);
      console.log(`   📦 ${exam.label} Q${start}-Q${end}...`);

      const batch = await structureBatch(examText, exam.label, start, end);
      if (batch.length > 0) {
        batch.forEach(q => { if (!q.examSection) q.examSection = exam.label; });
        allQuestions.push(...batch);
        console.log(`   ✅ +${batch.length} (total: ${allQuestions.length})`);
      } else {
        console.log(`   ⚠️ None returned`);
      }

      await new Promise(r => setTimeout(r, 2000));
    }
  }

  console.log(`\n📊 Total: ${allQuestions.length} questions`);
  if (allQuestions.length === 0) { console.error('❌ No questions extracted.'); process.exit(1); }

  // 5. Deduplicate
  const seen = new Set<string>();
  const unique = allQuestions.filter(q => {
    const id = generateId(q.examSection, q.questionNumber);
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  });
  console.log(`   🧹 Unique: ${unique.length}`);

  // 6. Upload
  console.log(`\n🔥 Uploading to Firestore (${PROJECT_ID})...`);
  const n = await uploadToFirestore(unique);
  console.log(`\n✅ Done! ${n} scenarios in "scenarios" collection.`);
}

main().catch(console.error);
