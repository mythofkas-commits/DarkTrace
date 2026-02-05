/**
 * PDF to Database Converter for DarkTrace
 * Uses Google Gemini AI to extract questions from practice exam PDFs
 *
 * Usage: npx ts-node scripts/pdf-to-database.ts
 */

import * as fs from 'fs';
import * as path from 'path';
import { GoogleGenerativeAI } from '@google/generative-ai';

// Load environment variables
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
  console.error('Please create a .env.local file with: GEMINI_API_KEY=your_api_key_here');
  process.exit(1);
}

const genAI = new GoogleGenerativeAI(GEMINI_API_KEY);

// Domain mapping for SY0-701 objectives
const DOMAIN_MAPPING: Record<string, string> = {
  '1': 'General Security Concepts',
  '2': 'Threats, Vulnerabilities, Mitigations',
  '3': 'Security Architecture',
  '4': 'Security Operations',
  '5': 'Governance, Risk, Compliance',
};

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

const EXTRACTION_PROMPT = `You are an expert at parsing CompTIA Security+ (SY0-701) practice exam questions.

Extract ALL questions from the following PDF text. For each question, provide:
1. The question number and which exam section it's from (e.g., "Exam A", "Exam B")
2. The full question text
3. All answer options (usually A, B, C, D)
4. Which option is correct (index 0-3)
5. The explanation for the correct answer
6. A rationale for each option (why it's correct or incorrect)
7. The SY0-701 objective codes (e.g., "1.1", "2.4", "5.5")
8. The domain based on objective codes:
   - 1.x = General Security Concepts
   - 2.x = Threats, Vulnerabilities, Mitigations
   - 3.x = Security Architecture
   - 4.x = Security Operations
   - 5.x = Governance, Risk, Compliance

Return a JSON array with this exact structure:
[
  {
    "questionNumber": 1,
    "examSection": "Exam A",
    "question": "Full question text here...",
    "options": ["Option A text", "Option B text", "Option C text", "Option D text"],
    "correctIndex": 0,
    "explanation": "Why the correct answer is right...",
    "rationales": [
      "CORRECT: Why A is right...",
      "INCORRECT: Why B is wrong...",
      "INCORRECT: Why C is wrong...",
      "INCORRECT: Why D is wrong..."
    ],
    "objectiveCodes": ["1.1", "1.2"],
    "domain": "General Security Concepts"
  }
]

IMPORTANT:
- Extract EVERY question you find
- Match rationales to the option order
- If explanations/rationales aren't provided, generate appropriate ones based on Security+ knowledge
- Keep the original question text exactly as written
- Return ONLY valid JSON, no markdown code blocks

PDF TEXT:
`;

async function extractTextFromPDF(pdfPath: string): Promise<string> {
  // Dynamic import for pdf-parse
  const pdfParse = (await import('pdf-parse')).default;
  const dataBuffer = fs.readFileSync(pdfPath);
  const data = await pdfParse(dataBuffer);
  return data.text;
}

async function extractQuestionsWithGemini(text: string, startPage: number = 0): Promise<ExtractedQuestion[]> {
  const model = genAI.getGenerativeModel({ model: 'gemini-1.5-pro' });

  // Split text into manageable chunks (roughly 30k chars each to stay under token limits)
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

      // Parse JSON from response
      let jsonStr = response;
      // Remove markdown code blocks if present
      if (jsonStr.includes('```json')) {
        jsonStr = jsonStr.replace(/```json\n?/g, '').replace(/```\n?/g, '');
      } else if (jsonStr.includes('```')) {
        jsonStr = jsonStr.replace(/```\n?/g, '');
      }

      try {
        const questions = JSON.parse(jsonStr.trim());
        if (Array.isArray(questions)) {
          allQuestions.push(...questions);
          console.log(`   ✅ Extracted ${questions.length} questions from chunk ${i + 1}`);
        }
      } catch (parseError) {
        console.error(`   ⚠️ Failed to parse JSON from chunk ${i + 1}, attempting recovery...`);
        // Try to find JSON array in response
        const jsonMatch = response.match(/\[[\s\S]*\]/);
        if (jsonMatch) {
          try {
            const questions = JSON.parse(jsonMatch[0]);
            allQuestions.push(...questions);
            console.log(`   ✅ Recovered ${questions.length} questions from chunk ${i + 1}`);
          } catch {
            console.error(`   ❌ Could not recover JSON from chunk ${i + 1}`);
          }
        }
      }

      // Rate limiting - wait between API calls
      if (i < chunks.length - 1) {
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    } catch (error) {
      console.error(`   ❌ API error on chunk ${i + 1}:`, error);
    }
  }

  return allQuestions;
}

function generateScenarioId(examSection: string, questionNumber: number): string {
  const sectionLetter = examSection.replace(/Exam\s*/i, '').charAt(0).toUpperCase() || 'X';
  return `EXAM-${sectionLetter}-Q${String(questionNumber).padStart(2, '0')}`;
}

function determineThreatLevel(domain: string, tags: string[]): 'low' | 'medium' | 'high' | 'critical' {
  const criticalKeywords = ['ransomware', 'ddos', 'apt', 'zero-day', 'rootkit', 'fileless'];
  const highKeywords = ['attack', 'exploit', 'breach', 'malware', 'injection', 'escalation'];
  const mediumKeywords = ['vulnerability', 'threat', 'risk', 'incident'];

  const allText = [...tags, domain].join(' ').toLowerCase();

  if (criticalKeywords.some(k => allText.includes(k))) return 'critical';
  if (highKeywords.some(k => allText.includes(k))) return 'high';
  if (mediumKeywords.some(k => allText.includes(k))) return 'medium';
  return 'low';
}

function generateTags(question: string, explanation: string): string[] {
  const tagKeywords: Record<string, string[]> = {
    'Cryptography': ['encrypt', 'hash', 'certificate', 'pki', 'key', 'cipher', 'aes', 'rsa'],
    'Network Security': ['firewall', 'ids', 'ips', 'vpn', 'network', 'packet', 'port'],
    'Authentication': ['mfa', 'password', 'biometric', 'sso', 'oauth', 'saml', 'ldap'],
    'Malware': ['virus', 'trojan', 'worm', 'ransomware', 'malware', 'rootkit'],
    'Social Engineering': ['phishing', 'vishing', 'smishing', 'pretexting', 'baiting'],
    'Cloud Security': ['cloud', 'saas', 'iaas', 'paas', 'aws', 'azure'],
    'Compliance': ['gdpr', 'hipaa', 'pci', 'sox', 'compliance', 'regulation'],
    'Incident Response': ['incident', 'forensic', 'response', 'investigation'],
    'Access Control': ['rbac', 'mac', 'dac', 'access control', 'permission'],
    'Risk Management': ['risk', 'assessment', 'mitigation', 'vulnerability'],
  };

  const text = `${question} ${explanation}`.toLowerCase();
  const tags: string[] = [];

  for (const [tag, keywords] of Object.entries(tagKeywords)) {
    if (keywords.some(k => text.includes(k))) {
      tags.push(tag);
    }
  }

  return tags.length > 0 ? tags.slice(0, 4) : ['Security Concepts'];
}

function generateLogs(question: string, domain: string): string[] {
  // Generate realistic-looking security logs based on question content
  const logTemplates: Record<string, string[]> = {
    'General Security Concepts': [
      'POLICY_ENGINE: Evaluating security control',
      'AUDIT_LOG: Configuration change detected',
    ],
    'Threats, Vulnerabilities, Mitigations': [
      'THREAT_INTEL: IOC match detected',
      'VULN_SCANNER: Assessment in progress',
    ],
    'Security Architecture': [
      'ARCH_REVIEW: Network topology validated',
      'CONFIG_AUDIT: Security baseline check',
    ],
    'Security Operations': [
      'SOC_ALERT: Anomaly detected in traffic',
      'SIEM_CORR: Event correlation triggered',
    ],
    'Governance, Risk, Compliance': [
      'COMPLIANCE_CHECK: Policy audit initiated',
      'RISK_ENGINE: Assessment score calculated',
    ],
  };

  return logTemplates[domain] || ['SYSTEM: Security event logged'];
}

function convertToScenario(q: ExtractedQuestion): string {
  const id = generateScenarioId(q.examSection, q.questionNumber);
  const tags = generateTags(q.question, q.explanation);
  const threatLevel = determineThreatLevel(q.domain, tags);
  const logs = generateLogs(q.question, q.domain);

  // Escape special characters in strings
  const escapeString = (s: string) => s.replace(/'/g, "\\'").replace(/\n/g, '\\n');

  return `  {
    id: '${id}',
    domain: '${q.domain}',
    question: '${escapeString(q.question)}',
    options: [${q.options.map(o => `'${escapeString(o)}'`).join(', ')}],
    correctIndex: ${q.correctIndex},
    explanation: '${escapeString(q.explanation)}',
    rationales: [
${q.rationales.map(r => `      '${escapeString(r)}'`).join(',\n')}
    ],
    objectiveCodes: [${q.objectiveCodes.map(c => `'${c}'`).join(', ')}],
    tags: [${tags.map(t => `'${t}'`).join(', ')}],
    threatLevel: '${threatLevel}',
    logs: [${logs.map(l => `'${l}'`).join(', ')}],
    refs: [{ source: 'Practice Exams', section: '${q.examSection}', page: ${q.questionNumber} }]
  }`;
}

async function main() {
  const pdfPath = path.join(__dirname, '..', 'SY0-701 Practice Exams.pdf');

  if (!fs.existsSync(pdfPath)) {
    console.error('❌ PDF file not found at:', pdfPath);
    console.error('\nPlease ensure "SY0-701 Practice Exams.pdf" is in the project root directory.');
    process.exit(1);
  }

  console.log('🚀 DarkTrace PDF to Database Converter');
  console.log('=====================================');
  console.log(`📁 Source: ${pdfPath}`);
  console.log('');

  // Step 1: Extract text from PDF
  console.log('📖 Step 1: Extracting text from PDF...');
  const pdfText = await extractTextFromPDF(pdfPath);
  console.log(`   ✅ Extracted ${pdfText.length.toLocaleString()} characters`);

  // Step 2: Use Gemini to extract questions
  console.log('\n🤖 Step 2: Using Gemini AI to extract questions...');
  const questions = await extractQuestionsWithGemini(pdfText);
  console.log(`   ✅ Total questions extracted: ${questions.length}`);

  if (questions.length === 0) {
    console.error('❌ No questions were extracted. Please check the PDF format.');
    process.exit(1);
  }

  // Step 3: Convert to TypeScript format
  console.log('\n📝 Step 3: Converting to TypeScript Scenario format...');
  const scenarioCode = questions.map(convertToScenario).join(',\n');

  // Step 4: Generate output file
  const outputContent = `
import { Scenario } from '../types';

// Auto-generated from "SY0-701 Practice Exams.pdf"
// Generated on: ${new Date().toISOString()}
// Total questions: ${questions.length}

export const scenarios: Scenario[] = [
${scenarioCode}
];
`;

  const outputPath = path.join(__dirname, '..', 'data', 'dataset-generated.ts');
  fs.writeFileSync(outputPath, outputContent);
  console.log(`   ✅ Output written to: ${outputPath}`);

  // Summary
  console.log('\n✨ Conversion Complete!');
  console.log('=======================');
  console.log(`📊 Statistics:`);
  console.log(`   - Total questions: ${questions.length}`);

  const domainCounts = questions.reduce((acc, q) => {
    acc[q.domain] = (acc[q.domain] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  console.log(`   - By domain:`);
  Object.entries(domainCounts).forEach(([domain, count]) => {
    console.log(`     • ${domain}: ${count}`);
  });

  console.log(`\n📌 Next steps:`);
  console.log(`   1. Review the generated file: data/dataset-generated.ts`);
  console.log(`   2. To use the new questions, update data/dataset.ts to import from dataset-generated.ts`);
  console.log(`   3. Or merge the questions manually into the existing dataset`);
}

main().catch(console.error);
