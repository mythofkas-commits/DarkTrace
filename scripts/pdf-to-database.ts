/**
 * PDF to Firestore Converter for DarkTrace
 * Uses Google Gemini 3 Flash Preview to extract questions from PDF
 * Uploads to Firestore in the exact Scenario schema from types.ts
 *
 * Prerequisites:
 *   1. Run: gcloud auth application-default login
 *   2. Ensure GEMINI_API_KEY is set in .env.local
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

// --- __dirname fix for ESM ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- ENV SETUP ---
const envPath = path.join(__dirname, '..', '.env.local');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf-8');
  envContent.split('\n').forEach(line => {
    const [key, ...valueParts] = line.split('=');
    if (key && valueParts.length > 0) process.env[key.trim()] = valueParts.join('=').trim();
  });
}

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
  console.error('❌ GEMINI_API_KEY not found in .env.local');
  process.exit(1);
}

// --- FIREBASE ADMIN SETUP ---
const FIREBASE_PROJECT_ID = 'gen-lang-client-0658504679';

initializeApp({
  credential: applicationDefault(),
  projectId: FIREBASE_PROJECT_ID
});
const db = getFirestore();

// --- GEMINI SETUP ---
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const fileManager = new GoogleAIFileManager(GEMINI_API_KEY);
const MODEL_NAME = 'gemini-3-flash-preview';

// --- VALID DOMAINS (from types.ts) ---
const VALID_DOMAINS = [
  'General Security Concepts',
  'Threats, Vulnerabilities, Mitigations',
  'Security Architecture',
  'Security Operations',
  'Governance, Risk, Compliance'
] as const;

// --- EXTRACTION PROMPT ---
const EXTRACTION_PROMPT = `
You are a Security+ (SY0-701) exam expert.
I have uploaded a practice exam PDF by Professor Messer.

TASK: Extract ALL questions from the specified exam section.

Return a JSON array. Each element MUST have this EXACT structure:

{
  "questionNumber": 1,
  "examSection": "Exam A",
  "question": "The full question text...",
  "options": ["Option A", "Option B", "Option C", "Option D"],
  "correctIndex": 0,
  "explanation": "Detailed explanation of why the correct answer is right...",
  "rationales": [
    "CORRECT: Why this option is correct.",
    "INCORRECT: Why this option is wrong.",
    "INCORRECT: Why this option is wrong.",
    "INCORRECT: Why this option is wrong."
  ],
  "objectiveCodes": ["1.2"],
  "domain": "General Security Concepts",
  "tags": ["Cryptography", "Hashing"],
  "threatLevel": "medium",
  "logs": ["SIEM_ALERT: Suspicious hash mismatch detected", "ACTION: File quarantined"],
  "page": 46
}

CRITICAL RULES:
1. Return ONLY valid JSON. No markdown code blocks, no explanation outside the JSON array.
2. "domain" MUST be one of these exact strings:
   - "General Security Concepts"
   - "Threats, Vulnerabilities, Mitigations"
   - "Security Architecture"
   - "Security Operations"
   - "Governance, Risk, Compliance"
3. "rationales" must have exactly 4 entries, one per option in order. Prefix each with "CORRECT:" or "INCORRECT:".
4. "threatLevel" must be one of: "low", "medium", "high", "critical"
5. "logs" should be 1-3 realistic SOC log entries related to the scenario. Use prefixes like SIEM_ALERT:, FW_LOG:, AUTH:, SCAN_RPT:, DNS_QUERY:, INCIDENT:, etc.
6. "tags" should be 2-4 specific Security+ topic keywords.
7. "objectiveCodes" should be the SY0-701 exam objective codes (e.g. ["2.4"]).
8. "page" should be the approximate PDF page number where this question appears.
9. Include the answer explanations from the PDF — they appear after each exam's questions.
`;

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
  const sectionLetter = examSection.replace(/Exam\s*/i, '').charAt(0).toUpperCase() || 'X';
  return `EXAM-${sectionLetter}-Q${String(questionNumber).padStart(2, '0')}`;
}

/**
 * Convert extracted question to Firestore document matching Scenario interface:
 * { id, domain, question, options, correctIndex, explanation, rationales,
 *   objectiveCodes, tags, threatLevel, logs, refs }
 */
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
      'CORRECT: See explanation.',
      'INCORRECT: See explanation.',
      'INCORRECT: See explanation.',
      'INCORRECT: See explanation.'
    ],
    objectiveCodes: q.objectiveCodes || [],
    tags: q.tags?.length ? q.tags : ['Security Concepts'],
    threatLevel: normalizeThreatLevel(q.threatLevel),
    logs: q.logs?.length ? q.logs : ['SYSTEM: Security event logged'],
    refs: [{
      source: 'Practice Exams',
      section: q.examSection || 'Exam A',
      ...(q.page ? { page: q.page } : {})
    }]
  };
}

// --- EXTRACTION ---
async function extractBatch(
  model: any,
  fileUri: string,
  fileMimeType: string,
  examLabel: string,
  startQ: number,
  endQ: number
): Promise<ExtractedQuestion[]> {
  const batchPrompt = `${EXTRACTION_PROMPT}

FOCUS: Extract questions ${startQ} through ${endQ} from "${examLabel}".
The answers/explanations for "${examLabel}" appear later in the PDF after the questions.
If you cannot find that exact range, extract whatever questions you can find from "${examLabel}".`;

  try {
    const result = await model.generateContent([
      {
        fileData: {
          mimeType: fileMimeType,
          fileUri: fileUri
        }
      },
      { text: batchPrompt }
    ]);

    const responseText = result.response.text();
    const jsonStr = responseText
      .replace(/```json\n?/g, '')
      .replace(/```\n?/g, '')
      .trim();

    const questions: ExtractedQuestion[] = JSON.parse(jsonStr);
    return Array.isArray(questions) ? questions : [];
  } catch (error: any) {
    console.error(`   ⚠️ Batch ${examLabel} Q${startQ}-${endQ} failed:`, error.message || error);
    return [];
  }
}

// --- FIRESTORE UPLOAD ---
async function uploadToFirestore(questions: ExtractedQuestion[]) {
  // Firestore batch limit is 500 writes
  const BATCH_LIMIT = 450;
  let total = 0;

  for (let i = 0; i < questions.length; i += BATCH_LIMIT) {
    const chunk = questions.slice(i, i + BATCH_LIMIT);
    const batch = db.batch();

    for (const q of chunk) {
      const data = toFirestoreDoc(q);
      const docRef = db.collection('scenarios').doc(data.id);
      batch.set(docRef, data);
    }

    await batch.commit();
    total += chunk.length;
    console.log(`   🔥 Committed batch: ${total}/${questions.length}`);
  }

  return total;
}

// --- MAIN ---
async function main() {
  const pdfPath = path.join(__dirname, '..', 'SY0-701 Practice Exams.pdf');

  if (!fs.existsSync(pdfPath)) {
    console.error('❌ PDF not found:', pdfPath);
    process.exit(1);
  }

  // 1. Upload PDF to Gemini
  console.log('🚀 Uploading PDF to Gemini...');
  const uploadResponse = await fileManager.uploadFile(pdfPath, {
    mimeType: 'application/pdf',
    displayName: 'SY0-701 Practice Exams',
  });
  console.log(`   ✅ Uploaded: ${uploadResponse.file.uri}`);

  // 2. Wait for processing
  console.log('   ⏳ Waiting for file processing...');
  let file = await fileManager.getFile(uploadResponse.file.name);
  while (file.state === 'PROCESSING') {
    process.stdout.write('.');
    await new Promise(r => setTimeout(r, 2000));
    file = await fileManager.getFile(uploadResponse.file.name);
  }
  if (file.state === 'FAILED') {
    console.error('\n❌ File processing failed.');
    process.exit(1);
  }
  console.log('\n   ✅ File Ready.');

  // 3. Extract in batches
  const model = genAI.getGenerativeModel({ model: MODEL_NAME });
  const allQuestions: ExtractedQuestion[] = [];

  // Messer practice exams: A through E, ~90 questions each
  const exams = ['Exam A', 'Exam B', 'Exam C', 'Exam D', 'Exam E'];
  const BATCH_SIZE = 45;
  const QS_PER_EXAM = 90;

  for (const exam of exams) {
    console.log(`\n🤖 Extracting ${exam}...`);
    for (let start = 1; start <= QS_PER_EXAM; start += BATCH_SIZE) {
      const end = Math.min(start + BATCH_SIZE - 1, QS_PER_EXAM);
      console.log(`   📦 ${exam} Q${start}-Q${end}...`);

      const batch = await extractBatch(
        model,
        uploadResponse.file.uri,
        uploadResponse.file.mimeType,
        exam,
        start,
        end
      );

      if (batch.length > 0) {
        batch.forEach(q => { if (!q.examSection) q.examSection = exam; });
        allQuestions.push(...batch);
        console.log(`   ✅ Got ${batch.length} questions`);
      } else {
        console.log(`   ⚠️ No questions returned`);
      }

      // Rate limit pause between batches
      await new Promise(r => setTimeout(r, 2000));
    }
  }

  console.log(`\n📊 Total extracted: ${allQuestions.length} questions`);

  if (allQuestions.length === 0) {
    console.error('❌ No questions extracted.');
    process.exit(1);
  }

  // 4. Deduplicate by ID
  const seen = new Set<string>();
  const unique: ExtractedQuestion[] = [];
  for (const q of allQuestions) {
    const id = generateId(q.examSection, q.questionNumber);
    if (!seen.has(id)) {
      seen.add(id);
      unique.push(q);
    }
  }
  console.log(`   🧹 After dedup: ${unique.length} unique questions`);

  // 5. Upload to Firestore
  console.log(`\n🔥 Uploading to Firestore (project: ${FIREBASE_PROJECT_ID})...`);
  console.log(`   Collection: "scenarios"`);
  const uploaded = await uploadToFirestore(unique);
  console.log(`\n✅ Done! ${uploaded} scenarios uploaded to Firestore.`);
  console.log(`\n💡 Next steps:`);
  console.log(`   1. Update utils/firebase.ts to use project "${FIREBASE_PROJECT_ID}"`);
  console.log(`   2. Update App.tsx to fetch from Firestore collection "scenarios" instead of importing dataset.ts`);
}

main().catch(console.error);
