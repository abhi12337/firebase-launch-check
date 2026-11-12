import { createUserWithEmailAndPassword } from "firebase/auth";
import { doc, setDoc } from "firebase/firestore";
import { auth, db } from "../lib/firebase";

export async function signUp(email: string, password: string) {
  const { user } = await createUserWithEmailAndPassword(auth, email, password);
  await setDoc(doc(db, "users", user.uid), {
    email,
    role: "member",
    plan: "free",
  });
}
