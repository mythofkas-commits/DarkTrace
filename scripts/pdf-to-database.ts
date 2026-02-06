import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url'; // <--- NEW IMPORT
import { GoogleGenerativeAI } from '@google/generative-ai';
import { initializeApp, applicationDefault } from 'firebase-admin/app';
import { getFirestore } from 'firebase-admin/firestore';

// --- FIX FOR __dirname IN ES MODULES ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// ---------------------------------------

// --- FIREBASE SETUP ---
// Initialize Admin SDK in "God Mode"
initializeApp({
  credential: applicationDefault(),
  projectId: "gen-lang-client-0658504679" // Ensure this matches your Firebase Config!
});

const db = getFirestore();

// --- REST OF CODE REMAINS THE SAME ---
const envPath = path.join(__dirname, '..', '.env.local');
// ...
// NOTE: For this to work locally, run: gcloud auth application-default login
initializeApp({
  credential: applicationDefault(),
  projectId: "gen-lang-client-0658504679" // Your specific Project ID
});

const db = getFirestore();

// --- ENV SETUP ---
const envPath = path.join(__dirname, '..', '.env.local');
if (fs.existsSync(envPath)) {
  const envContent = fs.readFileSync(envPath, 'utf-8');
  envContent.split('\n').forEach(line => {
    const [key, ...valueParts] = line.split('=');
    if (key && valueParts.length > 0) {
      process.env[key.trim()] = valueParts.join('=').trim();
    }
  });
}

const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
if (!GEMINI_API_KEY) {
  console.error('❌ GEMINI_API_KEY not found!');
  process.exit(1);
}

const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

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
}

// Prompt identical to before
const EXTRACTION_PROMPT = `You are an expert at parsing CompTIA Security+ (SY0-701) practice exam questions.

Extract ALL questions from the following PDF text. Return a JSON array with this exact structure:
[
  {
    "questionNumber": 1,
    "examSection": "Exam A",
    "question": "Full question text...",
    "options": ["A", "B", "C", "D"],
    "correctIndex": 0,
    "explanation": "...",
    "rationales": ["...", "...", "...", "..."],
    "objectiveCodes": ["1.1"],
    "domain": "General Security Concepts"
  }
]
IMPORTANT: Return ONLY valid JSON, no markdown.

PDF TEXT:
`;

async function extractTextFromPDF(pdfPath: string): Promise<string> {
  const pdfParse = (await import('pdf-parse')).default;
  const dataBuffer = fs.readFileSync(pdfPath);
  const data = await pdfParse(dataBuffer);
  return data.text;
}

async function extractQuestionsWithGemini(text: string): Promise<ExtractedQuestion[]> {
  const model = genAI.getGenerativeModel({ model: 'gemini-3-pro-preview' });
  const CHUNK_SIZE = 30000;
  const chunks: string[] = [];

  for (let i = 0; i < text.length; i += CHUNK_SIZE) {
    chunks.push(text.slice(i, i + CHUNK_SIZE));
  }

  console.log(`📄 Processing ${chunks.length} chunks of text...`);
  const allQuestions: ExtractedQuestion[] = [];

  for (let i = 0; i < chunks.length; i++) {
    console.log(`🔄 Processing chunk ${i + 1}/${chunks.length}...`);
    try {
      const result = await model.generateContent(EXTRACTION_PROMPT + chunks[i]);
      const response = result.response.text();
      let jsonStr = response.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();

      const questions = JSON.parse(jsonStr);
      if (Array.isArray(questions)) {
        allQuestions.push(...questions);
        console.log(`   ✅ Extracted ${questions.length} questions`);
      }
      
      if (i < chunks.length - 1) await new Promise(r => setTimeout(r, 2000));
    } catch (error) {
      console.error(`   ❌ Chunk ${i + 1} Error:`, error);
    }
  }
  return allQuestions;
}

// --- HELPER FUNCTIONS ---

function generateScenarioId(examSection: string, questionNumber: number): string {
  const sectionLetter = examSection.replace(/Exam\s*/i, '').charAt(0).toUpperCase() || 'X';
  return `EXAM-${sectionLetter}-Q${String(questionNumber).padStart(2, '0')}`;
}

function determineThreatLevel(domain: string, tags: string[]): string {
  const critical = ['ransomware', 'ddos', 'apt', 'zero-day'];
  const allText = [...tags, domain].join(' ').toLowerCase();
  if (critical.some(k => allText.includes(k))) return 'critical';
  return 'medium'; // Simplified default
}

function generateTags(question: string, explanation: string): string[] {
  // Simplified tagging logic
  const keywords = ['cryptography', 'network', 'malware', 'cloud', 'compliance'];
  const text = (question + explanation).toLowerCase();
  return keywords.filter(k => text.includes(k));
}

// CHANGED: Returns Object instead of String
function convertToFirestoreObject(q: ExtractedQuestion) {
  const id = generateScenarioId(q.examSection, q.questionNumber);
  const tags = generateTags(q.question, q.explanation);
  
  return {
    id: id, // Used as Document ID
    domain: q.domain,
    question: q.question,
    options: q.options,
    correctIndex: q.correctIndex,
    explanation: q.explanation,
    rationales: q.rationales,
    objectiveCodes: q.objectiveCodes,
    tags: tags.length ? tags : ['Security Concepts'],
    threatLevel: determineThreatLevel(q.domain, tags),
    logs: ['SYSTEM: Security event logged'], // Default log
    uploadedAt: new Date(),
    // SPACED REPETITION FIELDS
    reviewDue: new Date(), // Due immediately
    confidenceLevel: 0,    // Start at 0
    reviewHistory: []
  };
}

async function uploadToFirestore(questions: ExtractedQuestion[]) {
  console.log('\n🔥 Step 3: Uploading to Firestore...');
  
  const batch = db.batch();
  let count = 0;

  for (const q of questions) {
    const data = convertToFirestoreObject(q);
    const docRef = db.collection('questions').doc(data.id);
    batch.set(docRef, data);
    count++;
  }

  await batch.commit();
  console.log(`   ✅ Successfully uploaded ${count} questions to Firestore!`);
}

async function main() {
  const pdfPath = path.join(__dirname, '..', 'SY0-701 Practice Exams.pdf');

  if (!fs.existsSync(pdfPath)) {
    console.error('❌ PDF file not found at:', pdfPath);
    process.exit(1);
  }

  // 1. Extract Text
  console.log('📖 Extracting text...');
  const pdfText = await extractTextFromPDF(pdfPath);

  // 2. Parse with Gemini
  console.log('🤖 Parsing with Gemini...');
  const questions = await extractQuestionsWithGemini(pdfText);

  if (questions.length === 0) {
    console.error('❌ No questions found.');
    process.exit(1);
  }

  // 3. Upload to DB
  await uploadToFirestore(questions);
  
  console.log('\n✨ COMPLETE! Data is now live in your app.');
}

main().catch(console.error);
