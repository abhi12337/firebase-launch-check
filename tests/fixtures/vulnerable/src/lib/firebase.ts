import { initializeApp } from "firebase/app";
import { getAuth } from "firebase/auth";
import { getFirestore, connectFirestoreEmulator } from "firebase/firestore";
import { getStorage } from "firebase/storage";
import { getDatabase } from "firebase/database";

// The web config is public by design; security comes from the rules.
const app = initializeApp({
  apiKey: "demo-api-key",
  authDomain: "shop-demo.firebaseapp.com",
  projectId: "shop-demo",
  storageBucket: "shop-demo.appspot.com",
  databaseURL: "https://shop-demo-default-rtdb.firebaseio.com",
});

export const auth = getAuth(app);
export const db = getFirestore(app);
export const storage = getStorage(app);
export const rtdb = getDatabase(app);

connectFirestoreEmulator(db, "localhost", 8080);
