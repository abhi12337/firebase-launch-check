import { doc, setDoc } from "firebase/firestore";
import { db } from "../lib/firebase";

export async function saveProfile(uid: string, email: string) {
  await setDoc(doc(db, "users", uid), { email, displayName: email.split("@")[0] });
  const button = { role: "button", label: "Save" };   // an ARIA role, not a document field
  return button;
}
