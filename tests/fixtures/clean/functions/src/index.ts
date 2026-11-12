import { initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { onCall, HttpsError } from "firebase-functions/v2/https";

initializeApp();   // built-in credentials, no key file

export const makeAdmin = onCall(async (req) => {
  if (req.auth?.token.admin !== true) throw new HttpsError("permission-denied", "admins only");
  await getAuth().setCustomUserClaims(req.data.uid, { admin: true });
});
