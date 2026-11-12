import { initializeApp } from "firebase/app";
import { getFirestore, connectFirestoreEmulator } from "firebase/firestore";
import { getStorage } from "firebase/storage";
import { getDatabase } from "firebase/database";

const app = initializeApp({ apiKey: "demo-api-key", projectId: "shop-clean" });
export const db = getFirestore(app);
export const storage = getStorage(app);
export const rtdb = getDatabase(app);

if (import.meta.env.DEV) {
  connectFirestoreEmulator(db, "127.0.0.1", 8080);
}
