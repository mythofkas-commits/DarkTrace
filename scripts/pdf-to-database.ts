/**
 * PDF to Firestore — Split & OCR Approach
 * 
 * 1. Split 393-page PDF into 6 small chunks using pdf-lib (pure JS)
 * 2. Upload each chunk to Gemini separately
 * 3. OCR each chunk (small file = fast, no timeout)
 * 4. Structure OCR text into Scenario JSON with Flash
 * 5. Upload to Firestore
 *
 * Each Gemini call processes 30-95 pages instead of 393.
 * Cached after first run — re-runs skip OCR entirely.
 *
 * Usage: npx tsx scripts/pdf-to-database.ts
 */

import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { fileURLToPath } from 'url';
import { PDFDocument } from 'pdf-lib';
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
const FLASH_MODEL = 'gemini-3-flash-preview';
const REQUEST_TIMEOUT = { timeout: 300_000 };

// --- PDF STRUCTURE ---
// Page numbers are 1-indexed as they appear in PDF
const EXAM_CHUNKS = [
  { label: 'Exam A questions', startPage: 7,   endPage: 44,  exam: 'Exam A', type: 'questions' },
  { label: 'Exam A answers',   startPage: 45,  endPage: 139, exam: 'Exam A', type: 'answers'   },
  { label: 'Exam B questions', startPage: 140, endPage: 170, exam: 'Exam B', type: 'questions' },
  { label: 'Exam B answers',   startPage: 172, endPage: 265, exam: 'Exam B', type: 'answers'   },
  { label: 'Exam C questions', startPage: 266, endPage: 298, exam: 'Exam C', type: 'questions' },
  { label: 'Exam C answers',   startPage: 300, endPage: 392, exam: 'Exam C', type: 'answers'   },
];

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

interface StructuringCheckpoint {
  questions: ExtractedQuestion[];
  completedBatches: string[];
}

const OCR_FAILURE_PATTERNS = [
  'blank page',
  'blank pages',
  'blank white',
  'no text',
  'no visible text',
  'do not contain any text',
  'nothing to transcribe',
  'unable to transcribe',
  'please provide',
];

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
  const firstBracket = raw.indexOf('[');
  if (firstBracket === -1) return [];
  try { return JSON.parse(raw.slice(firstBracket, lastBrace + 1) + ']'); } catch { return []; }
}

function isLikelyOcrFailure(text: string): boolean {
  const lower = text.toLowerCase();
  return OCR_FAILURE_PATTERNS.some(p => lower.includes(p));
}

function hasExamQuestionSignal(text: string): boolean {
  return /\b\d{1,3}\.\s/.test(text) || /\bquestion\s+\d{1,3}\b/i.test(text);
}

function inspectPdfBinary(pdfPath: string): {
  replacementTriplets: number;
  sha256: string;
} {
  const buf = fs.readFileSync(pdfPath);
  let replacementTriplets = 0;
  for (let i = 0; i < buf.length - 2; i++) {
    if (buf[i] === 0xef && buf[i + 1] === 0xbf && buf[i + 2] === 0xbd) {
      replacementTriplets++;
    }
  }
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
  return { replacementTriplets, sha256 };
}

function loadStructuringCheckpoint(filePath: string): StructuringCheckpoint {
  if (!fs.existsSync(filePath)) return { questions: [], completedBatches: [] };
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf-8'));
    return {
      questions: Array.isArray(parsed?.questions) ? parsed.questions : [],
      completedBatches: Array.isArray(parsed?.completedBatches) ? parsed.completedBatches : [],
    };
  } catch {
    return { questions: [], completedBatches: [] };
  }
}

function saveStructuringCheckpoint(filePath: string, questions: ExtractedQuestion[], completedBatches: Set<string>) {
  const payload: StructuringCheckpoint = {
    questions,
    completedBatches: Array.from(completedBatches),
  };
  fs.writeFileSync(filePath, JSON.stringify(payload), 'utf-8');
}

// ============================================================
// PHASE 0: Split the PDF into small chunks with pdf-lib
// ============================================================
async function splitPdf(pdfPath: string, outputDir: string): Promise<Map<string, string>> {
  console.log('✂️  Splitting PDF into exam chunks...');

  const pdfBytes = fs.readFileSync(pdfPath);
  const srcDoc = await PDFDocument.load(pdfBytes);
  const totalPages = srcDoc.getPageCount();
  console.log(`   Source: ${totalPages} pages, ${(pdfBytes.length / 1024 / 1024).toFixed(1)} MB`);

  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const chunkFiles = new Map<string, string>();

  for (const chunk of EXAM_CHUNKS) {
    const outPath = path.join(outputDir, `${chunk.exam.replace(' ', '')}-${chunk.type}.pdf`);

    // Skip if already split
    if (fs.existsSync(outPath)) {
      const size = (fs.statSync(outPath).size / 1024).toFixed(0);
      console.log(`   📂 Cached: ${chunk.label} (${size} KB)`);
      chunkFiles.set(chunk.label, outPath);
      continue;
    }

    const newDoc = await PDFDocument.create();
    // pdf-lib uses 0-indexed pages
    const startIdx = chunk.startPage - 1;
    const endIdx = Math.min(chunk.endPage - 1, totalPages - 1);
    const indices = Array.from({ length: endIdx - startIdx + 1 }, (_, i) => startIdx + i);

    const pages = await newDoc.copyPages(srcDoc, indices);
    pages.forEach(p => newDoc.addPage(p));

    const outBytes = await newDoc.save();
    fs.writeFileSync(outPath, outBytes);

    const sizeKB = (outBytes.length / 1024).toFixed(0);
    console.log(`   ✅ ${chunk.label}: pp.${chunk.startPage}-${chunk.endPage} → ${sizeKB} KB (${indices.length} pages)`);
    chunkFiles.set(chunk.label, outPath);
  }

  return chunkFiles;
}

// ============================================================
// PHASE 1: OCR each small chunk (upload + read separately)
// ============================================================
async function ocrChunks(chunkFiles: Map<string, string>): Promise<string> {
  const cacheFile = path.join(__dirname, '..', '.ocr-cache.txt');
  const chunkCacheDir = path.join(__dirname, '..', '.ocr-cache-chunks');
  if (!fs.existsSync(chunkCacheDir)) fs.mkdirSync(chunkCacheDir, { recursive: true });
  const chunkCachePath = (label: string) =>
    path.join(chunkCacheDir, `${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.txt`);

  if (fs.existsSync(cacheFile)) {
    const cached = fs.readFileSync(cacheFile, 'utf-8');
    const hasAllSections = EXAM_CHUNKS.every(c => cached.includes(`=== ${c.label.toUpperCase()} ===`));
    if (cached.length > 5000 && hasAllSections && !isLikelyOcrFailure(cached)) {
      console.log(`   📂 Using cached OCR (${(cached.length / 1024).toFixed(0)} KB)`);
      return cached;
    }
    console.log('Cache invalid/stale, re-running OCR');
  }

  const model = genAI.getGenerativeModel(
    { model: FLASH_MODEL, generationConfig: { maxOutputTokens: 65536, temperature: 0 } },
    REQUEST_TIMEOUT
  );

  let fullText = '';

  for (const chunk of EXAM_CHUNKS) {
    const cachedPath = chunkCachePath(chunk.label);
    if (fs.existsSync(cachedPath)) {
      const cachedChunk = fs.readFileSync(cachedPath, 'utf-8');
      if (cachedChunk.length > 1000 && !isLikelyOcrFailure(cachedChunk) && hasExamQuestionSignal(cachedChunk)) {
        console.log(`   Using cached chunk OCR: ${chunk.label}`);
        fullText += `\n\n=== ${chunk.label.toUpperCase()} ===\n\n${cachedChunk}`;
        continue;
      }
    }

    const filePath = chunkFiles.get(chunk.label);
    if (!filePath) continue;

    console.log(`   📖 OCR: ${chunk.label}...`);

    // Upload this small chunk to Gemini
    let uploadUri: string;
    let uploadMime: string;
    try {
      const upload = await fileManager.uploadFile(filePath, {
        mimeType: 'application/pdf',
        displayName: chunk.label,
      });
      uploadUri = upload.file.uri;
      uploadMime = upload.file.mimeType;

      // Wait for processing
      let file = await fileManager.getFile(upload.file.name);
      while (file.state === 'PROCESSING') {
        await new Promise(r => setTimeout(r, 2000));
        file = await fileManager.getFile(upload.file.name);
      }
      if (file.state === 'FAILED') {
        console.log(`      ❌ Processing failed for ${chunk.label}, skipping`);
        continue;
      }
    } catch (err: any) {
      console.log(`      ❌ Upload failed: ${(err.message || '').slice(0, 80)}`);
      continue;
    }

    // OCR with retries
    let text = '';
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        const ocrPrompt = chunk.type === 'questions'
          ? `Transcribe ALL text from this PDF exactly as written.
Include every question number, the full question text, and all answer options (A/B/C/D).
Output plain text. Be thorough — do not skip any question.`
          : `Transcribe ALL text from this PDF exactly as written.
This contains answer explanations. Include every question number, the correct answer letter, and the full explanation text.
Output plain text. Be thorough — do not skip any answer.`;

        const result = await model.generateContent([
          { fileData: { mimeType: uploadMime, fileUri: uploadUri } },
          { text: ocrPrompt }
        ]);
        const candidate = result.response.text();
        if (isLikelyOcrFailure(candidate) || !hasExamQuestionSignal(candidate)) {
          throw new Error('OCR returned no usable question/answer content');
        }
        text = candidate;
        break;
      } catch (err: any) {
        const msg = err.message || String(err);
        console.log(`      ⚠️ Attempt ${attempt + 1}/3: ${msg.slice(0, 80)}`);
        if (attempt < 2) await new Promise(r => setTimeout(r, (attempt + 1) * 10000));
      }
    }

    if (text) {
      console.log(`      ✅ ${text.length} chars`);
      fs.writeFileSync(cachedPath, text, 'utf-8');
      fullText += `\n\n=== ${chunk.label.toUpperCase()} ===\n\n${text}`;
      fs.writeFileSync(cacheFile, fullText, 'utf-8');
    } else {
      console.log(`      ❌ OCR failed for ${chunk.label}`);
    }

    await new Promise(r => setTimeout(r, 3000));
  }

  if (isLikelyOcrFailure(fullText) || fullText.length < 20000) {
    throw new Error('OCR content is incomplete or mostly unreadable; refusing to continue to Phase 2.');
  }

  fs.writeFileSync(cacheFile, fullText, 'utf-8');
  console.log(`   💾 Cached OCR: ${(fullText.length / 1024).toFixed(0)} KB`);
  return fullText;
}

// ============================================================
// PHASE 2: Structure OCR text → Scenario JSON
// ============================================================
async function structureBatch(
  rawText: string, examLabel: string, startQ: number, endQ: number, retryCount = 0
): Promise<ExtractedQuestion[]> {
  const model = genAI.getGenerativeModel(
    {
      model: FLASH_MODEL,
      generationConfig: { maxOutputTokens: 65536, temperature: 0.1, responseMimeType: 'application/json' }
    },
    REQUEST_TIMEOUT
  );

  const prompt = `Below is OCR text from Professor Messer's SY0-701 Practice Exams.
It contains questions and answer explanations for "${examLabel}".

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
- JSON array ONLY. No markdown fences, no extra text.
- "domain" must be exactly one of: "General Security Concepts", "Threats, Vulnerabilities, Mitigations", "Security Architecture", "Security Operations", "Governance, Risk, Compliance"
- "rationales": exactly 4, matching option order, prefixed CORRECT:/INCORRECT:
- "correctIndex": 0-based index of correct option
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
      if (salvaged.length > 0) { console.log(`      🔧 Salvaged ${salvaged.length}`); return salvaged; }
      if (retryCount < 2 && endQ - startQ > 1) {
        const mid = Math.floor((startQ + endQ) / 2);
        console.log(`      🔄 Splitting Q${startQ}-${mid} + Q${mid+1}-${endQ}`);
        const a = await structureBatch(rawText, examLabel, startQ, mid, retryCount + 1);
        await new Promise(r => setTimeout(r, 2000));
        const b = await structureBatch(rawText, examLabel, mid + 1, endQ, retryCount + 1);
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

  const pdfInfo = inspectPdfBinary(pdfPath);
  if (pdfInfo.replacementTriplets > 1000) {
    console.error('âŒ PDF appears corrupted before OCR.');
    console.error(`   Detected UTF-8 replacement byte triplets: ${pdfInfo.replacementTriplets}`);
    console.error(`   SHA-256: ${pdfInfo.sha256}`);
    console.error('   This usually means the PDF binary was transcoded as text (ef bf bd bytes inserted).');
    console.error('   Replace "SY0-701 Practice Exams.pdf" with a clean original binary copy, then rerun.');
    process.exit(1);
  }

  const sizeMB = (fs.statSync(pdfPath).size / 1024 / 1024).toFixed(1);
  console.log(`📋 PDF: SY0-701 Practice Exams.pdf (${sizeMB} MB, 393 pages)`);
  console.log(`🧠 Strategy: Split PDF → OCR small chunks → Structure → Firestore`);
  console.log(`💰 Each Gemini call sees 30-95 pages instead of 393\n`);

  // Phase 0: Split
  console.log('═══ PHASE 0: SPLIT PDF ═══');
  const splitDir = path.join(__dirname, '..', '.pdf-chunks');
  const chunkFiles = await splitPdf(pdfPath, splitDir);
  console.log();

  // Phase 1: OCR each chunk
  console.log('═══ PHASE 1: OCR CHUNKS ═══');
  const ocrText = await ocrChunks(chunkFiles);
  console.log(`   📊 Total OCR: ${(ocrText.length / 1024).toFixed(0)} KB\n`);

  // Phase 2: Structure
  console.log('═══ PHASE 2: STRUCTURING ═══');
  const structCheckpointFile = path.join(__dirname, '..', '.structuring-checkpoint.json');
  const structCheckpoint = loadStructuringCheckpoint(structCheckpointFile);
  const completedBatches = new Set<string>(structCheckpoint.completedBatches);
  const allQuestions: ExtractedQuestion[] = [...structCheckpoint.questions];
  if (completedBatches.size > 0 || allQuestions.length > 0) {
    console.log(`   Resuming structuring checkpoint: ${completedBatches.size} batches, ${allQuestions.length} questions`);
  }

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
      console.log(`   📝 Section: ${(examText.length / 1024).toFixed(0)} KB`);
    } else {
      console.log(`   ⚠️ Couldn't isolate section, using full text`);
      examText = ocrText;
    }

    const BATCH = 10;
    for (let start = 1; start <= 90; start += BATCH) {
      const end = Math.min(start + BATCH - 1, 90);
      const batchKey = `${exam.label}:${start}-${end}`;
      if (completedBatches.has(batchKey)) {
        console.log(`   Skipping cached batch ${batchKey}`);
        continue;
      }
      console.log(`   📦 ${exam.label} Q${start}-Q${end}...`);

      const batch = await structureBatch(examText, exam.label, start, end);
      if (batch.length > 0) {
        batch.forEach(q => { if (!q.examSection) q.examSection = exam.label; });
        allQuestions.push(...batch);
        completedBatches.add(batchKey);
        saveStructuringCheckpoint(structCheckpointFile, allQuestions, completedBatches);
        console.log(`   ✅ +${batch.length} (total: ${allQuestions.length})`);
      } else {
        console.log(`   ⚠️ None returned`);
      }

      await new Promise(r => setTimeout(r, 2000));
    }
  }

  console.log(`\n📊 Total: ${allQuestions.length} questions`);
  if (allQuestions.length === 0) { console.error('❌ No questions extracted.'); process.exit(1); }

  // Deduplicate
  const seen = new Set<string>();
  const unique = allQuestions.filter(q => {
    const id = generateId(q.examSection, q.questionNumber);
    if (seen.has(id)) return false;
    seen.add(id); return true;
  });
  console.log(`   🧹 Unique: ${unique.length}`);

  // Upload
  console.log(`\n🔥 Uploading to Firestore (${PROJECT_ID})...`);
  const n = await uploadToFirestore(unique);
  if (fs.existsSync(structCheckpointFile)) fs.unlinkSync(structCheckpointFile);
  console.log(`\n✅ Done! ${n} scenarios in "scenarios" collection.`);
}

main().catch(console.error);
