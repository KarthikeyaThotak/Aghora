import { initializeApp } from 'firebase/app';
import { getAuth, GoogleAuthProvider, connectAuthEmulator } from 'firebase/auth';
import { getFirestore, connectFirestoreEmulator, enableNetwork, disableNetwork } from 'firebase/firestore';
import { getStorage, connectStorageEmulator } from 'firebase/storage';

const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};

// Initialize Firebase
const app = initializeApp(firebaseConfig);

// Initialize Firebase Authentication
export const auth = getAuth(app);

// Initialize Firestore with connection resilience
export const db = getFirestore(app);

// Initialize Firebase Storage
export const storage = getStorage(app);

// Configure Google Sign-In
export const googleProvider = new GoogleAuthProvider();

// Connection management utilities
export const connectionManager = {
  isOnline: navigator.onLine,
  
  async enableFirestore() {
    try {
      await enableNetwork(db);
      console.log('Firestore network enabled');
    } catch (error) {
      console.warn('Failed to enable Firestore network:', error);
    }
  },
  
  async disableFirestore() {
    try {
      await disableNetwork(db);
      console.log('Firestore network disabled');
    } catch (error) {
      console.warn('Failed to disable Firestore network:', error);
    }
  },
  
  async retryConnection(maxRetries = 3, delay = 1000) {
    for (let i = 0; i < maxRetries; i++) {
      try {
        await this.enableFirestore();
        return true;
      } catch (error) {
        console.warn(`Connection retry ${i + 1} failed:`, error);
        if (i < maxRetries - 1) {
          await new Promise(resolve => setTimeout(resolve, delay * (i + 1)));
        }
      }
    }
    return false;
  }
};

// Listen for online/offline events
window.addEventListener('online', () => {
  console.log('Network connection restored');
  connectionManager.enableFirestore();
});

window.addEventListener('offline', () => {
  console.log('Network connection lost');
  connectionManager.disableFirestore();
});

export default app;
