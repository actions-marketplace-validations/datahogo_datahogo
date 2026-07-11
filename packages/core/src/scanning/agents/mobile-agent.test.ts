import { describe, it, expect } from "vitest";
import { MobileScanAgent } from "./mobile-agent.js";

function makeFiles(entries: Record<string, string>): Map<string, string> {
  return new Map(Object.entries(entries));
}

const agent = new MobileScanAgent();

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EXPO_APP_JSON = JSON.stringify({
  expo: {
    name: "MyApp",
    slug: "myapp",
    version: "1.0.0",
    extra: {
      apiKey: "AIzaSyAbc123DefGhi456JklMno789PqrStuVwx",
      appId: "com.myapp",
    },
  },
}, null, 2);

const CLEAN_APP_JSON = JSON.stringify({
  expo: {
    name: "MyApp",
    slug: "myapp",
    version: "1.0.0",
    extra: {
      appId: "com.myapp",
      environment: "production",
    },
  },
}, null, 2);

const FLUTTER_PUBSPEC = `
name: myapp
description: A Flutter application.
version: 1.0.0

environment:
  sdk: ">=2.17.0 <3.0.0"

dependencies:
  flutter:
    sdk: flutter
  http: ^0.13.5
`;

const REACT_NATIVE_PACKAGE_JSON = JSON.stringify({
  name: "MyRNApp",
  version: "1.0.0",
  dependencies: {
    "react-native": "0.72.0",
    react: "18.2.0",
  },
});

const ANDROID_MANIFEST_CLEAN = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <application android:label="MyApp">
        <activity android:name=".MainActivity"/>
    </application>
</manifest>`;

const ANDROID_MANIFEST_EXCESSIVE = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_CONTACTS"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.READ_CALL_LOG"/>
    <uses-permission android:name="android.permission.READ_PHONE_STATE"/>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
    <application android:label="MyApp">
        <activity android:name=".MainActivity"/>
    </application>
</manifest>`;

const ANDROID_MANIFEST_DEEP_LINK_NO_VERIFY = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <data android:scheme="https" android:host="myapp.com"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`;

const ANDROID_MANIFEST_DEEP_LINK_WITH_VERIFY = `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application>
        <activity android:name=".MainActivity">
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.VIEW"/>
                <category android:name="android.intent.category.DEFAULT"/>
                <data android:scheme="https" android:host="myapp.com"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`;

const JS_WITH_HARDCODED_AWS = `
import { S3Client } from "@aws-sdk/client-s3";

const client = new S3Client({
  region: "us-east-1",
  credentials: {
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: process.env.AWS_SECRET_KEY,
  },
});
`;

// Split from the "sk_live_" prefix so no Stripe-key-shaped literal appears
// contiguously in source (avoids tripping GitHub push protection on our own
// fake fixture — these test the agent's secret-detection pass, not a real key).
const FAKE_STRIPE_KEY_SUFFIX = "abcdefghijklmnopqrstuvwx123456";

const JS_WITH_HARDCODED_STRIPE = `
import Stripe from "stripe";

const stripe = new Stripe("sk_live_${FAKE_STRIPE_KEY_SUFFIX}");
`;

const JS_WITH_HARDCODED_FIREBASE = `
const firebaseConfig = {
  apiKey: "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q",
  authDomain: "myapp.firebaseapp.com",
  projectId: "myapp",
};
`;

const JS_CLEAN_NO_KEYS = `
import { S3Client } from "@aws-sdk/client-s3";

const client = new S3Client({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_KEY,
  },
});
`;

const ENV_EXAMPLE_WITH_KEY = `
# Copy this file to .env and fill in values
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
STRIPE_KEY=sk_live_${FAKE_STRIPE_KEY_SUFFIX}
`;

const JS_ASYNC_STORAGE_TOKEN = `
import AsyncStorage from "@react-native-async-storage/async-storage";

async function saveSession(token: string) {
  await AsyncStorage.setItem("token", token);
}
`;

const JS_ASYNC_STORAGE_PASSWORD = `
import AsyncStorage from "@react-native-async-storage/async-storage";

async function saveCredentials(password: string) {
  await AsyncStorage.setItem("user_password", password);
}
`;

const JS_ASYNC_STORAGE_SAFE = `
import AsyncStorage from "@react-native-async-storage/async-storage";

async function saveTheme(theme: string) {
  await AsyncStorage.setItem("theme", theme);
}
`;

const DART_SHARED_PREFS_TOKEN = `
import 'package:shared_preferences/shared_preferences.dart';

Future<void> saveToken(String token) async {
  final prefs = await SharedPreferences.getInstance();
  prefs.setString('auth_token', token);
}
`;

const DART_SHARED_PREFS_SECURE = `
import 'package:shared_preferences/shared_preferences.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

Future<void> saveToken(String token) async {
  final storage = FlutterSecureStorage();
  await storage.write(key: 'auth_token', value: token);
}
`;

const DART_SHARED_PREFS_SAFE_KEY = `
import 'package:shared_preferences/shared_preferences.dart';

Future<void> saveTheme(String theme) async {
  final prefs = await SharedPreferences.getInstance();
  prefs.setString('theme_preference', theme);
}
`;

const JS_WEBVIEW_WITH_JS_NO_WHITELIST = `
import { WebView } from "react-native-webview";

export function Browser({ url }: { url: string }) {
  return (
    <WebView
      source={{ uri: url }}
      javaScriptEnabled={true}
    />
  );
}
`;

const JS_WEBVIEW_WITH_WHITELIST = `
import { WebView } from "react-native-webview";

export function Browser({ url }: { url: string }) {
  return (
    <WebView
      source={{ uri: url }}
      javaScriptEnabled={true}
      originWhitelist={["https://myapp.com"]}
    />
  );
}
`;

const JS_NO_WEBVIEW = `
import { Text, View } from "react-native";

export function Hello() {
  return <View><Text>Hello</Text></View>;
}
`;

const JS_WITH_NETWORK_NO_PINNING = `
import axios from "axios";

export async function fetchUser(id: string) {
  const response = await axios.get(\`https://api.example.com/users/\${id}\`);
  return response.data;
}
`;

const EXPO_CONSTANTS_SENSITIVE = `
import Constants from "expo-constants";

const apiKey = Constants.expoConfig.extra.apiKey;
const appId = Constants.expoConfig.extra.appId;
`;

const EXPO_CONSTANTS_SAFE = `
import Constants from "expo-constants";

const appName = Constants.expoConfig.name;
const version = Constants.expoConfig.version;
`;

const JS_WITH_MANY_CONSOLE_LOGS = `
function processData(data: unknown) {
  console.log("Starting processing", data);
  console.log("Step 1 done");
  console.log("Step 2 done");
  console.log("Step 3 done");
  console.log("Processing complete");
  console.log("Step 4 done");
  console.log("Step 5 done");
  console.log("Step 6 done");
  console.log("Step 7 done");
  console.log("Step 8 done");
  return data;
}
`;

const JS_WITH_DEV_GUARD = `
function processData(data: unknown) {
  if (__DEV__) {
    console.log("Starting processing", data);
    console.log("Step 1 done");
    console.log("Step 2 done");
    console.log("Step 3 done");
    console.log("Processing complete");
  }
  return data;
}
`;

const JS_WITH_FEW_LOGS = `
function processData(data: unknown) {
  console.log("Done");
  return data;
}
`;

const DART_WITH_MANY_PRINTS = `
void processData(dynamic data) {
  print('Starting processing');
  print('Step 1 done');
  print('Step 2 done');
  print('Step 3 done');
  print('Processing complete');
  print('Step 4 done');
  print('Step 5 done');
  print('Step 6 done');
  print('Step 7 done');
  print('Step 8 done');
}
`;

const DART_WITH_DEBUG_GUARD = `
import 'package:flutter/foundation.dart';

void processData(dynamic data) {
  if (kDebugMode) {
    print('Starting processing');
    print('Step 1 done');
    print('Step 2 done');
    print('Step 3 done');
    print('Processing complete');
  }
}
`;

const JS_BIOMETRICS_NO_SERVER = `
import * as LocalAuthentication from "expo-local-authentication";

async function authenticate() {
  const result = await LocalAuthentication.authenticateAsync({
    promptMessage: "Authenticate to proceed",
  });
  if (result.success) {
    navigateToHome();
  }
}
`;

const JS_BIOMETRICS_WITH_SERVER = `
import * as LocalAuthentication from "expo-local-authentication";

async function authenticate() {
  const result = await LocalAuthentication.authenticateAsync({
    promptMessage: "Authenticate to proceed",
  });
  if (result.success) {
    const token = await verifyWithServer(result);
    navigateToHome(token);
  }
}
`;

const DART_HTTP_ENDPOINT = `
import 'package:http/http.dart' as http;

Future<void> fetchData() async {
  final response = await http.get(Uri.parse('http://api.mycompany.com/data'));
  processResponse(response);
}
`;

const DART_HTTPS_ENDPOINT = `
import 'package:http/http.dart' as http;

Future<void> fetchData() async {
  final response = await http.get(Uri.parse('https://api.mycompany.com/data'));
  processResponse(response);
}
`;

const JS_DOTENV_SENSITIVE = `
import { SECRET_API_KEY, APP_ENV } from "@env";

const client = createClient(SECRET_API_KEY);
`;

const JS_DOTENV_SAFE = `
import { APP_NAME, APP_ENV } from "@env";

console.log(\`Running \${APP_NAME} in \${APP_ENV}\`);
`;

const JS_LOCAL_STORAGE_TOKEN = `
function saveSession(token: string) {
  localStorage.setItem("session_token", token);
}
`;

const JS_LOCAL_STORAGE_SAFE = `
function saveTheme(theme: string) {
  localStorage.setItem("theme", theme);
}
`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("MobileScanAgent", () => {
  // -------------------------------------------------------------------------
  // getMetadata()
  // -------------------------------------------------------------------------

  describe("getMetadata()", () => {
    it("returns correct agent name and version", () => {
      const meta = agent.getMetadata();
      expect(meta.name).toBe("mobile-agent");
      expect(meta.version).toBe("1.0.0");
    });

    it("returns all expected technologies", () => {
      const meta = agent.getMetadata();
      expect(meta.technologies).toEqual(["react-native", "expo", "dart", "flutter"]);
    });
  });

  // -------------------------------------------------------------------------
  // detect()
  // -------------------------------------------------------------------------

  describe("detect()", () => {
    it("detects Expo project via app.json with 'expo' content", async () => {
      const files = makeFiles({ "app.json": EXPO_APP_JSON });
      expect(await agent.detect(files)).toBe(true);
    });

    it("does not detect non-Expo app.json (no 'expo' key)", async () => {
      const files = makeFiles({ "app.json": '{"name":"myapp","version":"1.0"}' });
      expect(await agent.detect(files)).toBe(false);
    });

    it("detects Flutter project via pubspec.yaml with 'flutter' content", async () => {
      const files = makeFiles({ "pubspec.yaml": FLUTTER_PUBSPEC });
      expect(await agent.detect(files)).toBe(true);
    });

    it("does not detect non-Flutter pubspec.yaml", async () => {
      const files = makeFiles({ "pubspec.yaml": "name: mylib\nversion: 1.0.0\n" });
      expect(await agent.detect(files)).toBe(false);
    });

    it("detects Android project via AndroidManifest.xml at root", async () => {
      const files = makeFiles({ "AndroidManifest.xml": ANDROID_MANIFEST_CLEAN });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects Android project via AndroidManifest.xml in nested path", async () => {
      const files = makeFiles({
        "android/app/src/main/AndroidManifest.xml": ANDROID_MANIFEST_CLEAN,
      });
      expect(await agent.detect(files)).toBe(true);
    });

    it("detects React Native project via package.json dependency", async () => {
      const files = makeFiles({ "package.json": REACT_NATIVE_PACKAGE_JSON });
      expect(await agent.detect(files)).toBe(true);
    });

    it("does not detect plain web package.json", async () => {
      const files = makeFiles({
        "package.json": '{"name":"web-app","dependencies":{"next":"14.0.0"}}',
      });
      expect(await agent.detect(files)).toBe(false);
    });

    it("returns false for an empty file map", async () => {
      expect(await agent.detect(new Map())).toBe(false);
    });

    it("returns false for a Python-only project", async () => {
      const files = makeFiles({
        "requirements.txt": "flask==2.0.0",
        "app.py": "from flask import Flask",
      });
      expect(await agent.detect(files)).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // Check 1: Hardcoded API keys
  // -------------------------------------------------------------------------

  describe("scan() — hardcoded API keys", () => {
    it("detects AWS access key in JS source", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "src/storage.ts": JS_WITH_HARDCODED_AWS,
      });
      const results = await agent.scan(files);
      const awsResult = results.find((r) => r.title.includes("AWS Access Key"));
      expect(awsResult).toBeDefined();
      expect(awsResult!.severity).toBe("CRITICAL");
      expect(awsResult!.cwe).toBe("CWE-798");
    });

    it("detects Stripe live key in JS source", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "src/payment.ts": JS_WITH_HARDCODED_STRIPE,
      });
      const results = await agent.scan(files);
      const stripeResult = results.find((r) => r.title.includes("Stripe Secret Key"));
      expect(stripeResult).toBeDefined();
      expect(stripeResult!.severity).toBe("CRITICAL");
    });

    it("detects Firebase/Google API key in JS source", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "src/firebase.ts": JS_WITH_HARDCODED_FIREBASE,
      });
      const results = await agent.scan(files);
      const firebaseResult = results.find((r) => r.title.includes("Firebase/Google API Key"));
      expect(firebaseResult).toBeDefined();
      expect(firebaseResult!.severity).toBe("CRITICAL");
    });

    it("does not flag environment variable references", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "src/storage.ts": JS_CLEAN_NO_KEYS,
      });
      const results = await agent.scan(files);
      const keyResults = results.filter((r) => r.cwe === "CWE-798" && r.file === "src/storage.ts");
      expect(keyResults).toHaveLength(0);
    });

    it("ignores .env.example files", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        ".env.example": ENV_EXAMPLE_WITH_KEY,
      });
      const results = await agent.scan(files);
      const keyResults = results.filter(
        (r) => r.cwe === "CWE-798" && r.file === ".env.example",
      );
      expect(keyResults).toHaveLength(0);
    });

    it("detects hardcoded key in Dart files", async () => {
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/config.dart": 'const apiKey = "AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q";',
      });
      const results = await agent.scan(files);
      const dartKeyResult = results.find(
        (r) => r.title.includes("Firebase/Google API Key") && r.file === "lib/config.dart",
      );
      expect(dartKeyResult).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 2: AsyncStorage for sensitive data
  // -------------------------------------------------------------------------

  describe("scan() — AsyncStorage for sensitive data", () => {
    it("detects token stored in AsyncStorage", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/auth.ts": JS_ASYNC_STORAGE_TOKEN,
      });
      const results = await agent.scan(files);
      const asyncResult = results.find(
        (r) => r.title === "Sensitive data stored in AsyncStorage",
      );
      expect(asyncResult).toBeDefined();
      expect(asyncResult!.severity).toBe("HIGH");
      expect(asyncResult!.cwe).toBe("CWE-922");
    });

    it("detects password stored in AsyncStorage", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/auth.ts": JS_ASYNC_STORAGE_PASSWORD,
      });
      const results = await agent.scan(files);
      const asyncResult = results.find(
        (r) => r.title === "Sensitive data stored in AsyncStorage",
      );
      expect(asyncResult).toBeDefined();
    });

    it("does not flag non-sensitive keys in AsyncStorage", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/settings.ts": JS_ASYNC_STORAGE_SAFE,
      });
      const results = await agent.scan(files);
      const asyncResult = results.find(
        (r) => r.title === "Sensitive data stored in AsyncStorage",
      );
      expect(asyncResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 3: SharedPreferences for sensitive data
  // -------------------------------------------------------------------------

  describe("scan() — SharedPreferences for sensitive data", () => {
    it("detects auth token stored in SharedPreferences", async () => {
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/auth.dart": DART_SHARED_PREFS_TOKEN,
      });
      const results = await agent.scan(files);
      const spResult = results.find(
        (r) => r.title === "Sensitive data stored in SharedPreferences",
      );
      expect(spResult).toBeDefined();
      expect(spResult!.severity).toBe("HIGH");
      expect(spResult!.cwe).toBe("CWE-922");
    });

    it("does not flag when flutter_secure_storage is imported", async () => {
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/auth.dart": DART_SHARED_PREFS_SECURE,
      });
      const results = await agent.scan(files);
      const spResult = results.find(
        (r) => r.title === "Sensitive data stored in SharedPreferences",
      );
      expect(spResult).toBeUndefined();
    });

    it("does not flag non-sensitive keys in SharedPreferences", async () => {
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/settings.dart": DART_SHARED_PREFS_SAFE_KEY,
      });
      const results = await agent.scan(files);
      const spResult = results.find(
        (r) => r.title === "Sensitive data stored in SharedPreferences",
      );
      expect(spResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 4: Excessive Android permissions
  // -------------------------------------------------------------------------

  describe("scan() — excessive Android permissions", () => {
    it("flags AndroidManifest with 6+ sensitive permissions", async () => {
      const files = makeFiles({
        "AndroidManifest.xml": ANDROID_MANIFEST_EXCESSIVE,
      });
      const results = await agent.scan(files);
      const permResult = results.find(
        (r) => r.title === "Excessive Android permissions declared",
      );
      expect(permResult).toBeDefined();
      expect(permResult!.severity).toBe("MEDIUM");
      expect(permResult!.cwe).toBe("CWE-250");
    });

    it("does not flag AndroidManifest with fewer than 6 sensitive permissions", async () => {
      const files = makeFiles({
        "AndroidManifest.xml": ANDROID_MANIFEST_CLEAN,
      });
      const results = await agent.scan(files);
      const permResult = results.find(
        (r) => r.title === "Excessive Android permissions declared",
      );
      expect(permResult).toBeUndefined();
    });

    it("lists the sensitive permissions in the description", async () => {
      const files = makeFiles({
        "AndroidManifest.xml": ANDROID_MANIFEST_EXCESSIVE,
      });
      const results = await agent.scan(files);
      const permResult = results.find(
        (r) => r.title === "Excessive Android permissions declared",
      );
      expect(permResult!.description).toContain("READ_SMS");
      expect(permResult!.description).toContain("CAMERA");
    });
  });

  // -------------------------------------------------------------------------
  // Check 5: Expo config with secrets
  // -------------------------------------------------------------------------

  describe("scan() — Expo config with secrets", () => {
    it("detects secret value in app.json extra block", async () => {
      const files = makeFiles({ "app.json": EXPO_APP_JSON });
      const results = await agent.scan(files);
      const expoResult = results.find(
        (r) => r.title === "Secret value in Expo config extra block",
      );
      expect(expoResult).toBeDefined();
      expect(expoResult!.severity).toBe("CRITICAL");
      expect(expoResult!.cwe).toBe("CWE-798");
    });

    it("does not flag when extra block has no secret-sounding keys", async () => {
      const files = makeFiles({ "app.json": CLEAN_APP_JSON });
      const results = await agent.scan(files);
      const expoResult = results.find(
        (r) => r.title === "Secret value in Expo config extra block",
      );
      expect(expoResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 6: Deep links without autoVerify
  // -------------------------------------------------------------------------

  describe("scan() — deep links without autoVerify", () => {
    it("flags HTTPS intent-filter without autoVerify", async () => {
      const files = makeFiles({
        "AndroidManifest.xml": ANDROID_MANIFEST_DEEP_LINK_NO_VERIFY,
      });
      const results = await agent.scan(files);
      const linkResult = results.find(
        (r) => r.title === "Deep link intent-filter missing autoVerify",
      );
      expect(linkResult).toBeDefined();
      expect(linkResult!.severity).toBe("HIGH");
      expect(linkResult!.cwe).toBe("CWE-939");
    });

    it("does not flag intent-filter with android:autoVerify=true", async () => {
      const files = makeFiles({
        "AndroidManifest.xml": ANDROID_MANIFEST_DEEP_LINK_WITH_VERIFY,
      });
      const results = await agent.scan(files);
      const linkResult = results.find(
        (r) => r.title === "Deep link intent-filter missing autoVerify",
      );
      expect(linkResult).toBeUndefined();
    });

    it("does not flag custom scheme intent-filters (http scheme not HTTPS App Link)", async () => {
      const customSchemeManifest = `<?xml version="1.0" encoding="utf-8"?>
<manifest>
    <application>
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW"/>
                <data android:scheme="myapp" android:host="open"/>
            </intent-filter>
        </activity>
    </application>
</manifest>`;
      const files = makeFiles({ "AndroidManifest.xml": customSchemeManifest });
      const results = await agent.scan(files);
      const linkResult = results.find(
        (r) => r.title === "Deep link intent-filter missing autoVerify",
      );
      expect(linkResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 7: WebView with JavaScript enabled
  // -------------------------------------------------------------------------

  describe("scan() — WebView with JavaScript enabled", () => {
    it("flags WebView with javaScriptEnabled but no originWhitelist", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/browser.tsx": JS_WEBVIEW_WITH_JS_NO_WHITELIST,
      });
      const results = await agent.scan(files);
      const webViewResult = results.find(
        (r) => r.title === "WebView with JavaScript enabled and no URL whitelist",
      );
      expect(webViewResult).toBeDefined();
      expect(webViewResult!.severity).toBe("HIGH");
      expect(webViewResult!.cwe).toBe("CWE-749");
    });

    it("does not flag WebView with javaScriptEnabled AND originWhitelist", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/browser.tsx": JS_WEBVIEW_WITH_WHITELIST,
      });
      const results = await agent.scan(files);
      const webViewResult = results.find(
        (r) => r.title === "WebView with JavaScript enabled and no URL whitelist",
      );
      expect(webViewResult).toBeUndefined();
    });

    it("does not flag file without WebView", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/hello.tsx": JS_NO_WEBVIEW,
      });
      const results = await agent.scan(files);
      const webViewResult = results.find(
        (r) => r.title === "WebView with JavaScript enabled and no URL whitelist",
      );
      expect(webViewResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 8: Missing certificate pinning
  // -------------------------------------------------------------------------

  describe("scan() — missing certificate pinning", () => {
    it("flags project with network calls and no pinning library", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/api.ts": JS_WITH_NETWORK_NO_PINNING,
      });
      const results = await agent.scan(files);
      const pinningResult = results.find(
        (r) => r.title === "No certificate pinning detected",
      );
      expect(pinningResult).toBeDefined();
      expect(pinningResult!.severity).toBe("MEDIUM");
      expect(pinningResult!.cwe).toBe("CWE-295");
    });

    it("does not flag project with TrustKit configured", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/api.ts": JS_WITH_NETWORK_NO_PINNING,
        "src/pinning.ts": "// Configure TrustKit for certificate pinning\nimport TrustKit from 'react-native-trust-kit';",
      });
      const results = await agent.scan(files);
      const pinningResult = results.find(
        (r) => r.title === "No certificate pinning detected",
      );
      expect(pinningResult).toBeUndefined();
    });

    it("does not flag project with no network calls", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/math.ts": "export function add(a: number, b: number) { return a + b; }",
      });
      const results = await agent.scan(files);
      const pinningResult = results.find(
        (r) => r.title === "No certificate pinning detected",
      );
      expect(pinningResult).toBeUndefined();
    });

    it("does not flag project with rn-ssl-pinning configured", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/api.ts": JS_WITH_NETWORK_NO_PINNING,
        "src/network.ts": "import { fetch } from 'rn-ssl-pinning';",
      });
      const results = await agent.scan(files);
      const pinningResult = results.find(
        (r) => r.title === "No certificate pinning detected",
      );
      expect(pinningResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 9: Debug code in production
  // -------------------------------------------------------------------------

  describe("scan() — debug code in production", () => {
    it("flags 10+ console.log calls without __DEV__ guard in RN", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/process.ts": JS_WITH_MANY_CONSOLE_LOGS,
      });
      const results = await agent.scan(files);
      const debugResult = results.find(
        (r) => r.title === "Excessive console.log calls without __DEV__ guard",
      );
      expect(debugResult).toBeDefined();
      expect(debugResult!.severity).toBe("MEDIUM");
      expect(debugResult!.cwe).toBe("CWE-489");
    });

    it("does not flag when __DEV__ guard is present", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/process.ts": JS_WITH_DEV_GUARD,
      });
      const results = await agent.scan(files);
      const debugResult = results.find(
        (r) => r.title === "Excessive console.log calls without __DEV__ guard",
      );
      expect(debugResult).toBeUndefined();
    });

    it("does not flag files with fewer than 10 console.log calls", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/process.ts": JS_WITH_FEW_LOGS,
      });
      const results = await agent.scan(files);
      const debugResult = results.find(
        (r) => r.title === "Excessive console.log calls without __DEV__ guard",
      );
      expect(debugResult).toBeUndefined();
    });

    it("does not flag test files", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/__tests__/process.test.ts": JS_WITH_MANY_CONSOLE_LOGS,
      });
      const results = await agent.scan(files);
      const debugResult = results.find(
        (r) => r.title === "Excessive console.log calls without __DEV__ guard",
      );
      expect(debugResult).toBeUndefined();
    });

    it("flags 10+ print() calls without kDebugMode guard in Flutter", async () => {
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/process.dart": DART_WITH_MANY_PRINTS,
      });
      const results = await agent.scan(files);
      const debugResult = results.find(
        (r) => r.title === "Excessive print/debugPrint calls without kDebugMode guard",
      );
      expect(debugResult).toBeDefined();
      expect(debugResult!.severity).toBe("MEDIUM");
      expect(debugResult!.cwe).toBe("CWE-489");
    });

    it("does not flag Flutter file with kDebugMode guard", async () => {
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/process.dart": DART_WITH_DEBUG_GUARD,
      });
      const results = await agent.scan(files);
      const debugResult = results.find(
        (r) => r.title === "Excessive print/debugPrint calls without kDebugMode guard",
      );
      expect(debugResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 10: Biometric auth without server verification
  // -------------------------------------------------------------------------

  describe("scan() — biometric auth without server verification", () => {
    it("flags authenticateAsync without server token", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/auth.ts": JS_BIOMETRICS_NO_SERVER,
      });
      const results = await agent.scan(files);
      const bioResult = results.find(
        (r) => r.title === "Biometric authentication without server-side verification",
      );
      expect(bioResult).toBeDefined();
      expect(bioResult!.severity).toBe("MEDIUM");
      expect(bioResult!.cwe).toBe("CWE-287");
    });

    it("does not flag biometrics when server token verification is present", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/auth.ts": JS_BIOMETRICS_WITH_SERVER,
      });
      const results = await agent.scan(files);
      const bioResult = results.find(
        (r) => r.title === "Biometric authentication without server-side verification",
      );
      expect(bioResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 11: React Native dotenv exposure
  // -------------------------------------------------------------------------

  describe("scan() — react-native-dotenv exposure", () => {
    it("flags sensitive variable imported from @env", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/config.ts": JS_DOTENV_SENSITIVE,
      });
      const results = await agent.scan(files);
      const dotenvResult = results.find(
        (r) => r.title === "Sensitive variable exposed via react-native-dotenv",
      );
      expect(dotenvResult).toBeDefined();
      expect(dotenvResult!.severity).toBe("HIGH");
      expect(dotenvResult!.cwe).toBe("CWE-200");
    });

    it("does not flag non-sensitive imports from @env", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/config.ts": JS_DOTENV_SAFE,
      });
      const results = await agent.scan(files);
      const dotenvResult = results.find(
        (r) => r.title === "Sensitive variable exposed via react-native-dotenv",
      );
      expect(dotenvResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 12: Flutter debug endpoint
  // -------------------------------------------------------------------------

  describe("scan() — Flutter debug mode endpoint", () => {
    it("flags non-localhost HTTP URL in production Dart code", async () => {
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/api.dart": DART_HTTP_ENDPOINT,
      });
      const results = await agent.scan(files);
      const endpointResult = results.find(
        (r) => r.title === "Insecure HTTP endpoint in Flutter source",
      );
      expect(endpointResult).toBeDefined();
      expect(endpointResult!.severity).toBe("LOW");
      expect(endpointResult!.cwe).toBe("CWE-489");
    });

    it("does not flag HTTPS endpoints", async () => {
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/api.dart": DART_HTTPS_ENDPOINT,
      });
      const results = await agent.scan(files);
      const endpointResult = results.find(
        (r) => r.title === "Insecure HTTP endpoint in Flutter source",
      );
      expect(endpointResult).toBeUndefined();
    });

    it("does not flag when kReleaseMode conditional is present", async () => {
      const dartWithConditional = `
import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

final baseUrl = kReleaseMode
    ? 'https://api.mycompany.com'
    : 'http://localhost:8080';

Future<void> fetchData() async {
  final response = await http.get(Uri.parse('\$baseUrl/data'));
  processResponse(response);
}
`;
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/api.dart": dartWithConditional,
      });
      const results = await agent.scan(files);
      const endpointResult = results.find(
        (r) => r.title === "Insecure HTTP endpoint in Flutter source",
      );
      expect(endpointResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 13: Expo Constants exposure
  // -------------------------------------------------------------------------

  describe("scan() — Expo Constants exposure", () => {
    it("flags sensitive key accessed via Constants.expoConfig.extra", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "src/config.ts": EXPO_CONSTANTS_SENSITIVE,
      });
      const results = await agent.scan(files);
      const constantsResult = results.find(
        (r) => r.title === "Sensitive key accessed via Expo Constants.extra",
      );
      expect(constantsResult).toBeDefined();
      expect(constantsResult!.severity).toBe("HIGH");
      expect(constantsResult!.cwe).toBe("CWE-200");
    });

    it("does not flag Constants used without .extra access", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "src/config.ts": EXPO_CONSTANTS_SAFE,
      });
      const results = await agent.scan(files);
      const constantsResult = results.find(
        (r) => r.title === "Sensitive key accessed via Expo Constants.extra",
      );
      expect(constantsResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Check 14: Insecure data storage
  // -------------------------------------------------------------------------

  describe("scan() — insecure data storage", () => {
    it("flags localStorage.setItem with sensitive key in React Native", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/auth.ts": JS_LOCAL_STORAGE_TOKEN,
      });
      const results = await agent.scan(files);
      const storageResult = results.find(
        (r) => r.title === "Insecure use of localStorage in React Native",
      );
      expect(storageResult).toBeDefined();
      expect(storageResult!.severity).toBe("MEDIUM");
      expect(storageResult!.cwe).toBe("CWE-922");
    });

    it("does not flag localStorage with non-sensitive key", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/settings.ts": JS_LOCAL_STORAGE_SAFE,
      });
      const results = await agent.scan(files);
      const storageResult = results.find(
        (r) => r.title === "Insecure use of localStorage in React Native",
      );
      expect(storageResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Clean project — zero findings
  // -------------------------------------------------------------------------

  describe("scan() — clean project", () => {
    it("returns zero findings for a clean React Native project", async () => {
      const cleanRNSource = `
import React from "react";
import { View, Text } from "react-native";
import * as SecureStore from "expo-secure-store";

async function saveToken(token: string) {
  await SecureStore.setItemAsync("session", token);
}

export default function App() {
  return (
    <View>
      <Text>Hello, World!</Text>
    </View>
  );
}
`;
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "App.tsx": cleanRNSource,
      });
      const results = await agent.scan(files);

      // The clean project may still trigger cert pinning if axios is found
      // — exclude that project-level check from this assertion.
      const fileFindings = results.filter((r) => r.file !== "project");
      expect(fileFindings).toHaveLength(0);
    });

    it("returns zero findings for a clean Flutter project", async () => {
      const cleanDartSource = `
import 'package:flutter/material.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

final _storage = FlutterSecureStorage();

Future<void> saveToken(String token) async {
  await _storage.write(key: 'session', value: token);
}

void main() => runApp(MyApp());
`;
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/main.dart": cleanDartSource,
      });
      const results = await agent.scan(files);
      const fileFindings = results.filter((r) => r.file !== "project");
      expect(fileFindings).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // getChecks()
  // -------------------------------------------------------------------------

  describe("getChecks()", () => {
    const VALID_SEVERITIES = new Set(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]);

    it("returns non-empty array of check definitions", () => {
      const agent = new MobileScanAgent();
      expect(agent.getChecks().length).toBeGreaterThan(0);
    });

    it("every check has required fields", () => {
      const agent = new MobileScanAgent();
      for (const check of agent.getChecks()) {
        expect(check.id).toBeTruthy();
        expect(check.name).toBeTruthy();
        expect(VALID_SEVERITIES.has(check.severity)).toBe(true);
      }
    });

    it("check IDs are unique", () => {
      const agent = new MobileScanAgent();
      const ids = agent.getChecks().map((c) => c.id);
      expect(new Set(ids).size).toBe(ids.length);
    });

    it("check IDs follow mobile: prefix convention", () => {
      const agent = new MobileScanAgent();
      for (const check of agent.getChecks()) {
        expect(check.id).toMatch(/^mobile:/);
      }
    });

    it("scan findings have checkIds matching declared checks", async () => {
      const agent = new MobileScanAgent();
      const declaredIds = new Set(agent.getChecks().map((c) => c.id));

      // Build a comprehensive file map that exercises all checks across the
      // three mobile ecosystems (React Native / Expo / Flutter / Android).
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "AndroidManifest.xml": ANDROID_MANIFEST_EXCESSIVE,
        "src/payment.ts": JS_WITH_HARDCODED_STRIPE,
        "src/auth.ts": JS_ASYNC_STORAGE_TOKEN,
        "src/browser.tsx": JS_WEBVIEW_WITH_JS_NO_WHITELIST,
        "src/process.ts": JS_WITH_MANY_CONSOLE_LOGS,
        "src/biometrics.ts": JS_BIOMETRICS_NO_SERVER,
        "src/config.ts": EXPO_CONSTANTS_SENSITIVE,
        "src/dotenv.ts": JS_DOTENV_SENSITIVE,
        "src/storage.ts": JS_LOCAL_STORAGE_TOKEN,
        "lib/auth.dart": DART_SHARED_PREFS_TOKEN,
        "lib/api.dart": DART_HTTP_ENDPOINT,
        "lib/process.dart": DART_WITH_MANY_PRINTS,
      });

      const results = await agent.scan(files);
      expect(results.length).toBeGreaterThan(0);

      for (const result of results) {
        if (result.checkId !== undefined) {
          expect(declaredIds.has(result.checkId)).toBe(true);
        }
      }
    });
  });

  // -------------------------------------------------------------------------
  // Confidence field
  // -------------------------------------------------------------------------

  describe("scan() — confidence field", () => {
    it("hardcoded API key findings have confidence: high", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "src/payment.ts": JS_WITH_HARDCODED_STRIPE,
      });
      const results = await agent.scan(files);
      const keyResult = results.find((r) => r.title.includes("Stripe Secret Key"));
      expect(keyResult).toBeDefined();
      expect(keyResult!.confidence).toBe("high");
    });

    it("deep link without autoVerify findings have confidence: high", async () => {
      const files = makeFiles({
        "AndroidManifest.xml": ANDROID_MANIFEST_DEEP_LINK_NO_VERIFY,
      });
      const results = await agent.scan(files);
      const linkResult = results.find((r) => r.title === "Deep link intent-filter missing autoVerify");
      expect(linkResult).toBeDefined();
      expect(linkResult!.confidence).toBe("high");
    });

    it("missing certificate pinning findings have confidence: low", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/api.ts": JS_WITH_NETWORK_NO_PINNING,
      });
      const results = await agent.scan(files);
      const pinResult = results.find((r) => r.title === "No certificate pinning detected");
      expect(pinResult).toBeDefined();
      expect(pinResult!.confidence).toBe("low");
    });

    it("biometric without server verification findings have confidence: low", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/auth.ts": JS_BIOMETRICS_NO_SERVER,
      });
      const results = await agent.scan(files);
      const bioResult = results.find((r) => r.title === "Biometric authentication without server-side verification");
      expect(bioResult).toBeDefined();
      expect(bioResult!.confidence).toBe("low");
    });

    it("excessive permissions findings have confidence: low", async () => {
      const files = makeFiles({
        "AndroidManifest.xml": ANDROID_MANIFEST_EXCESSIVE,
      });
      const results = await agent.scan(files);
      const permResult = results.find((r) => r.title === "Excessive Android permissions declared");
      expect(permResult).toBeDefined();
      expect(permResult!.confidence).toBe("low");
    });

    it("AsyncStorage sensitive data findings have confidence: medium", async () => {
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/auth.ts": JS_ASYNC_STORAGE_TOKEN,
      });
      const results = await agent.scan(files);
      const asyncResult = results.find((r) => r.title === "Sensitive data stored in AsyncStorage");
      expect(asyncResult).toBeDefined();
      expect(asyncResult!.confidence).toBe("medium");
    });

    it("Expo config secrets findings have confidence: high", async () => {
      const files = makeFiles({ "app.json": EXPO_APP_JSON });
      const results = await agent.scan(files);
      const expoResult = results.find((r) => r.title === "Secret value in Expo config extra block");
      expect(expoResult).toBeDefined();
      expect(expoResult!.confidence).toBe("high");
    });
  });

  // -------------------------------------------------------------------------
  // Expo config false positive prevention
  // -------------------------------------------------------------------------

  describe("scan() — Expo config safe keys (no false positives)", () => {
    it("does not flag apiUrl key in extra block", async () => {
      const appJson = JSON.stringify({
        expo: {
          extra: { apiUrl: "https://api.myapp.com", apiEndpoint: "https://api.myapp.com/v1" },
        },
      }, null, 2);
      const files = makeFiles({ "app.json": appJson });
      const results = await agent.scan(files);
      const expoResult = results.find((r) => r.title === "Secret value in Expo config extra block");
      expect(expoResult).toBeUndefined();
    });

    it("does not flag apiEndpoint, apiHost, apiBase, apiPath keys in extra block", async () => {
      const appJson = JSON.stringify({
        expo: {
          extra: {
            apiEndpoint: "https://api.myapp.com",
            apiHost: "api.myapp.com",
            apiBase: "https://api.myapp.com",
            apiPath: "/v1",
          },
        },
      }, null, 2);
      const files = makeFiles({ "app.json": appJson });
      const results = await agent.scan(files);
      const expoResult = results.find((r) => r.title === "Secret value in Expo config extra block");
      expect(expoResult).toBeUndefined();
    });

    it("does not flag appId or appName keys in extra block", async () => {
      const appJson = JSON.stringify({
        expo: {
          extra: { appId: "com.myapp", appName: "My App" },
        },
      }, null, 2);
      const files = makeFiles({ "app.json": appJson });
      const results = await agent.scan(files);
      const expoResult = results.find((r) => r.title === "Secret value in Expo config extra block");
      expect(expoResult).toBeUndefined();
    });

    it("still flags apiKey (a real secret) in extra block", async () => {
      const appJson = JSON.stringify({
        expo: {
          extra: { apiKey: "AIzaSyAbc123DefGhi456JklMno789PqrStuVwx" },
        },
      }, null, 2);
      const files = makeFiles({ "app.json": appJson });
      const results = await agent.scan(files);
      const expoResult = results.find((r) => r.title === "Secret value in Expo config extra block");
      expect(expoResult).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // WebView wildcard originWhitelist
  // -------------------------------------------------------------------------

  describe("scan() — WebView wildcard originWhitelist", () => {
    it("flags WebView with javaScriptEnabled and originWhitelist=['*']", async () => {
      const jsWebViewWildcard = `
import { WebView } from "react-native-webview";

export function Browser({ url }: { url: string }) {
  return (
    <WebView
      source={{ uri: url }}
      javaScriptEnabled={true}
      originWhitelist={['*']}
    />
  );
}
`;
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/browser.tsx": jsWebViewWildcard,
      });
      const results = await agent.scan(files);
      const webViewResult = results.find(
        (r) => r.title === "WebView with JavaScript enabled and no URL whitelist",
      );
      expect(webViewResult).toBeDefined();
    });

    it('flags WebView with javaScriptEnabled and originWhitelist={["*"]}', async () => {
      const jsWebViewWildcard = `
import { WebView } from "react-native-webview";

export function Browser({ url }: { url: string }) {
  return (
    <WebView
      source={{ uri: url }}
      javaScriptEnabled={true}
      originWhitelist={["*"]}
    />
  );
}
`;
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/browser.tsx": jsWebViewWildcard,
      });
      const results = await agent.scan(files);
      const webViewResult = results.find(
        (r) => r.title === "WebView with JavaScript enabled and no URL whitelist",
      );
      expect(webViewResult).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // Flutter debug endpoint — localhost exemptions
  // -------------------------------------------------------------------------

  describe("scan() — Flutter debug endpoint localhost exemptions", () => {
    it("does not flag http://127.0.0.1 URLs", async () => {
      const dartWith127 = `
import 'package:http/http.dart' as http;

Future<void> fetchData() async {
  final response = await http.get(Uri.parse('http://127.0.0.1:8080/data'));
  processResponse(response);
}
`;
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/api.dart": dartWith127,
      });
      const results = await agent.scan(files);
      const endpointResult = results.find(
        (r) => r.title === "Insecure HTTP endpoint in Flutter source",
      );
      expect(endpointResult).toBeUndefined();
    });

    it("does not flag http://10.0.2.2 URLs (Android emulator loopback)", async () => {
      const dartWithEmulator = `
import 'package:http/http.dart' as http;

Future<void> fetchData() async {
  final response = await http.get(Uri.parse('http://10.0.2.2:8080/api'));
  processResponse(response);
}
`;
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/api.dart": dartWithEmulator,
      });
      const results = await agent.scan(files);
      const endpointResult = results.find(
        (r) => r.title === "Insecure HTTP endpoint in Flutter source",
      );
      expect(endpointResult).toBeUndefined();
    });

    it("still flags non-localhost http:// URLs", async () => {
      const files = makeFiles({
        "pubspec.yaml": FLUTTER_PUBSPEC,
        "lib/api.dart": DART_HTTP_ENDPOINT,
      });
      const results = await agent.scan(files);
      const endpointResult = results.find(
        (r) => r.title === "Insecure HTTP endpoint in Flutter source",
      );
      expect(endpointResult).toBeDefined();
    });
  });

  // -------------------------------------------------------------------------
  // Debug code — process.env.NODE_ENV guard
  // -------------------------------------------------------------------------

  describe("scan() — debug code NODE_ENV guard", () => {
    it("does not flag console.log when process.env.NODE_ENV check is present", async () => {
      const jsWithNodeEnvGuard = `
function processData(data: unknown) {
  if (process.env.NODE_ENV !== 'production') {
    console.log("Starting processing", data);
    console.log("Step 1 done");
    console.log("Step 2 done");
    console.log("Step 3 done");
    console.log("Step 4 done");
    console.log("Step 5 done");
    console.log("Step 6 done");
    console.log("Step 7 done");
    console.log("Step 8 done");
    console.log("Step 9 done");
    console.log("Step 10 done");
  }
  return data;
}
`;
      const files = makeFiles({
        "package.json": REACT_NATIVE_PACKAGE_JSON,
        "src/process.ts": jsWithNodeEnvGuard,
      });
      const results = await agent.scan(files);
      const debugResult = results.find(
        (r) => r.title === "Excessive console.log calls without __DEV__ guard",
      );
      expect(debugResult).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // Result structure
  // -------------------------------------------------------------------------

  describe("scan() — result structure", () => {
    it("every result has all required ScanResult fields", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "AndroidManifest.xml": ANDROID_MANIFEST_EXCESSIVE,
        "src/payment.ts": JS_WITH_HARDCODED_STRIPE,
        "src/auth.ts": JS_ASYNC_STORAGE_TOKEN,
      });
      const results = await agent.scan(files);
      expect(results.length).toBeGreaterThan(0);

      for (const result of results) {
        expect(typeof result.title).toBe("string");
        expect(result.title.length).toBeGreaterThan(0);
        expect(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]).toContain(result.severity);
        expect(typeof result.file).toBe("string");
        expect(typeof result.line).toBe("number");
        expect(result.line).toBeGreaterThan(0);
        expect(typeof result.description).toBe("string");
        expect(result.description.length).toBeGreaterThan(0);
        expect(typeof result.fix).toBe("string");
        expect(result.fix.length).toBeGreaterThan(0);
      }
    });

    it("results with CWE reference use the correct format", async () => {
      const files = makeFiles({
        "app.json": EXPO_APP_JSON,
        "src/payment.ts": JS_WITH_HARDCODED_STRIPE,
      });
      const results = await agent.scan(files);
      const withCwe = results.filter((r) => r.cwe !== undefined);
      expect(withCwe.length).toBeGreaterThan(0);
      for (const result of withCwe) {
        expect(result.cwe).toMatch(/^CWE-\d+$/);
      }
    });
  });
});
