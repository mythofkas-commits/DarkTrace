/**
 * PDF to Database Converter for DarkTrace
 * Uses Google Gemini 3 Flash + Native File API
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

// --- FIX FOR __dirname ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- FIREBASE SETUP ---
initializeApp({
  credential: applicationDefault(),
  projectId: "gen-lang-client-0658504679"
});
const db = getFirestore();

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

// Initialize Clients
const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);
const fileManager = new GoogleAIFileManager(GEMINI_API_KEY);

// UPDATED: Using Gemini 3 Flash (Current Standard)
const MODEL_NAME = 'gemini-3-flash'; 

const EXTRACTION_PROMPT = `
You are a Security+ (SY0-701) exam expert. 
I have uploaded a practice exam PDF. 

TASK:
Extract questions from the exam. Because this is a PDF, watch out for headers/footers breaking text.
Return a JSON array with this exact structure:
[
  {
    "questionNumber": 1,
    "examSection": "Exam A",
    "question": "The full question text...",
    "options": ["Option A", "Option B", "Option C", "Option D"],
    "correctIndex": 0,
    "explanation": "Detailed explanation...",
    "rationales": ["Why A is correct", "Why B is wrong", "Why C is wrong", "Why D is wrong"],
    "objectiveCodes": ["1.2"],
    "domain": "Threats, Vulnerabilities, and Mitigations"
  }
]

IMPORTANT:
- Return ONLY valid JSON.
- No Markdown code blocks.
- Extract as many questions as possible (up to 50 per batch if possible).
`;

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

// --- HELPER FUNCTIONS ---
function generateScenarioId(examSection: string, questionNumber: number): string {
  const sectionLetter = examSection.replace(/Exam\s*/i, '').charAt(0).toUpperCase() || 'X';
  return `EXAM-${sectionLetter}-Q${String(questionNumber).padStart(2, '0')}`;
}

function determineThreatLevel(domain: string, tags: string[]): string {
  const critical = ['ransomware', 'ddos', 'apt', 'zero-day', 'rootkit'];
  const allText = [...tags, domain].join(' ').toLowerCase();
  if (critical.some(k => allText.includes(k))) return 'critical';
  return 'medium';
}

function generateTags(question: string, explanation: string): string[] {
  const keywords = ['cryptography', 'network', 'malware', 'cloud', 'compliance', 'iot', 'mobile'];
  const text = (question + explanation).toLowerCase();
  return keywords.filter(k => text.includes(k));
}

function convertToFirestoreObject(q: ExtractedQuestion) {
  const id = generateScenarioId(q.examSection, q.questionNumber);
  const tags = generateTags(q.question, q.explanation);
  
  return {
    id: id,
    domain: q.domain,
    question: q.question,
    options: q.options,
    correctIndex: q.correctIndex,
    explanation: q.explanation,
    rationales: q.rationales,
    objectiveCodes: q.objectiveCodes,
    tags: tags.length ? tags : ['Security Concepts'],
    threatLevel: determineThreatLevel(q.domain, tags),
    logs: ['SYSTEM: Security event logged'],
    uploadedAt: new Date(),
    reviewDue: new Date(), // Immediate review
    confidenceLevel: 0,
    reviewHistory: []
  };
}

async function uploadToFirestore(questions: ExtractedQuestion[]) {
  const batch = db.batch();
  let count = 0;
  
  console.log(`\n🔥 Uploading ${questions.length} questions to Firestore...`);

  for (const q of questions) {
    const data = convertToFirestoreObject(q);
    const docRef = db.collection('questions').doc(data.id);
    batch.set(docRef, data);
    count++;
  }

  await batch.commit();
  console.log(`   ✅ Batch committed: ${count} questions saved.`);
}

async function main() {
  const pdfPath = path.join(__dirname, '..', 'SY0-701 Practice Exams.pdf');
  
  if (!fs.existsSync(pdfPath)) {
    console.error('❌ PDF not found:', pdfPath);
    process.exit(1);
  }

  // 1. Upload File to Google
  console.log('🚀 Uploading PDF to Gemini 3...');
  const uploadResponse = await fileManager.uploadFile(pdfPath, {
    mimeType: "application/pdf",
    displayName: "SY0-701 Exam",
  });
  
  console.log(`   ✅ Uploaded: ${uploadResponse.file.uri}`);
  console.log('   ⏳ Waiting for file processing...');

  // 2. Wait for Processing (Active Polling)
  let file = await fileManager.getFile(uploadResponse.file.name);
  while (file.state === "PROCESSING") {
    process.stdout.write(".");
    await new Promise((resolve) => setTimeout(resolve, 2000));
    file = await fileManager.getFile(uploadResponse.file.name);
  }
  
  if (file.state === "FAILED") {
    console.error("❌ Video processing failed.");
    process.exit(1);
  }
  console.log('\n   ✅ File Ready.');

  // 3. Generate Content
  console.log(`\n🤖 Extracting with ${MODEL_NAME}...`);
  const model = genAI.getGenerativeModel({ model: MODEL_NAME });

  try {
    const result = await model.generateContent([
      {
        fileData: {
          mimeType: uploadResponse.file.mimeType,
          fileUri: uploadResponse.file.uri
        }
      },
      { text: EXTRACTION_PROMPT }
    ]);

    const responseText = result.response.text();
    // Clean JSON (Gemini 3 sometimes adds markdown blocks)
    const jsonStr = responseText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    
    const questions = JSON.parse(jsonStr);
    
    if (Array.isArray(questions) && questions.length > 0) {
      console.log(`   ✅ Extracted ${questions.length} questions.`);
      await uploadToFirestore(questions);
    } else {
      console.error('❌ No questions found in response.');
      console.log('Raw Response:', responseText.slice(0, 500));
    }

  } catch (error) {
    console.error('❌ Error during generation:', error);
  }
}

main().catch(console.error);
