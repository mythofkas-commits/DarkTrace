import { initializeApp } from "firebase/app";
import { getAnalytics, isSupported } from "firebase/analytics";
import { getAuth } from "firebase/auth";
import { getFirestore } from "firebase/firestore";

// Updated configuration from user
const firebaseConfig = {
  apiKey: "AIzaSyCHoHtgyR9SNBax5NnTpPyUhIw3wwgcdn8",
  authDomain: "aaaaa-ca9a6.firebaseapp.com",
  projectId: "aaaaa-ca9a6",
  storageBucket: "aaaaa-ca9a6.firebasestorage.app",
  messagingSenderId: "67655718873",
  appId: "1:67655718873:web:4915df3a73f52d787f2bc8"
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
