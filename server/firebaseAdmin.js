import admin from 'firebase-admin';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import fs from 'fs';

let serviceAccount;

if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    // ✅ Running on Render (or cloud) → Load from ENV variable
    serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
} else {
    // ✅ Running Locally → Load from serviceAccountKey.json
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);

    serviceAccount = JSON.parse(
        fs.readFileSync(path.join(__dirname, '../serviceAccountKey.json'), 'utf8')
    );
}

// ✅ Initialize Firebase Admin SDK
if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
}

// ✅ Export Firestore & Auth Admin
export const db = admin.firestore();
export const authAdmin = admin.auth();
export { admin };
