import { initializeApp } from "firebase/app";
import { getAnalytics, isSupported } from "firebase/analytics";

// For Firebase JS SDK v7.20.0 and later, measurementId is optional
const firebaseConfig = {
  apiKey: "AIzaSyCuFFfPZ36TOQF1HrBF6RyZPaxRGnASXjY",
  authDomain: "darktrace-91535.firebaseapp.com",
  projectId: "darktrace-91535",
  storageBucket: "darktrace-91535.firebasestorage.app",
  messagingSenderId: "170403701401",
  appId: "1:170403701401:web:d049fafbd09a9877b2ce08",
  measurementId: "G-7YXY6YERB3"
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

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

export { app, analytics };
