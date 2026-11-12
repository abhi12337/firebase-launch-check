import admin from "firebase-admin";

export async function promote(uid: string) {
  await admin.auth().setCustomUserClaims(uid, { admin: true });
}
