import { initializeApp } from "firebase/app";
import { getAnalytics, isSupported } from "firebase/analytics";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

const firebaseConfig = {
  apiKey: "AIzaSyAMzmqqETec9BUcKd0eZAehMAUkRUITDhc",
  authDomain: "gen-lang-client-0658504679.firebaseapp.com",
  projectId: "gen-lang-client-0658504679",
  storageBucket: "gen-lang-client-0658504679.firebasestorage.app",
  messagingSenderId: "1030995064919",
  appId: "1:1030995064919:web:af846b58e2ce48fd360b12",
  measurementId: "G-YQET0MC1SF"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);

// Initialize Analytics conditionally to prevent errors in unsupported environments
let analytics = null;

try {
  isSupported().then((supported) => {
    if (supported) {
      try {
        analytics = getAnalytics(app);
      } catch (e) {
        console.warn("Analytics initialization failed:", e);
      }
    }
  }).catch((e) => {
    console.warn("Analytics not supported in this environment:", e);
  });
} catch (e) {
  console.warn("Firebase initialization warning:", e);
}

export { app, analytics, auth, db };
