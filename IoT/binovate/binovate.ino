#include <ESP32Servo.h>
#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <mbedtls/md.h>

// ---------------- WIFI ----------------
const char* ssid = "Armeen";
const char* password = "whxu7743";

// ---------------- PINS ----------------
const int SOUND_PIN = 33;
const int SERVO_PIN = 32;
const int LED_PIN = 2;

// thresholds for sound
const int THRESHOLD_ON  = 2200;
const int THRESHOLD_OFF = 2000;

// Ultrasonic pins
const int TRIG_PIN = 13;          
const int ECHO_PIN = 34;          

// Settings
const int NUM_SAMPLES = 10;
const int OPEN_TIME = 200;       
const int OPEN_DURATION = 5000;  
const float MAX_DISTANCE_CM = 16.0;

// ---------------- BACKEND ----------------
const char* backendURL = "https://binovate.onrender.com/api/v1/binovate/status";
const char* SECRET = "f3e0d5c8c7f8467c9d2b4a8e34c6a1e0b7f9d9a5a2f442e7a0c2e5d3b8f7c4e9";
const char* BIN_ID = "006";

// ---------------- GLOBALS ----------------
Servo myServo;
bool mic_on = true;
unsigned long lastPostTime = 0;
const unsigned long POST_INTERVAL = 60000;

// ---------------- FUNCTIONS ----------------
int readMicAverage(int pin, int samples = NUM_SAMPLES) {
  long sum = 0;
  for (int i = 0; i < samples; i++) {
    sum += analogRead(pin);
    delay(2);
  }
  return sum / samples;
}

String hmacSha256(const char* key, const char* message) {
  unsigned char output[32];
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char*)key, strlen(key));
  mbedtls_md_hmac_update(&ctx, (const unsigned char*)message, strlen(message));
  mbedtls_md_hmac_finish(&ctx, output);
  mbedtls_md_free(&ctx);

  String hashStr = "";
  for (int i = 0; i < 32; i++) {
    if (output[i] < 16) hashStr += "0";
    hashStr += String(output[i], HEX);
  }
  hashStr.toLowerCase();
  return hashStr;
}

void sendBinData(float percentFull) { // ใช้ส่ง Request ไปหา Server
  if (WiFi.status() != WL_CONNECTED) return;

  HTTPClient http;
  http.begin(backendURL);
  http.addHeader("Content-Type", "application/json");

  String timestamp = String(millis() / 1000);
  String plainText = String(BIN_ID) + timestamp;
  String shaHeader = hmacSha256(SECRET, plainText.c_str());
  http.addHeader("signature", shaHeader);

  StaticJsonDocument<200> doc;
  doc["bin_id"] = String(BIN_ID);
  doc["timestamp"] = String(timestamp);
  doc["status"] = String((int)percentFull);
  doc["location"] = "Dormitory";

  String payload;
  serializeJson(doc, payload);

  int httpResponseCode = http.PUT(payload); 
  if(httpResponseCode > 0){
    Serial.print("PUT sent. Code: "); Serial.println(httpResponseCode);
    Serial.print("Payload: "); Serial.println(payload);
  } else {
    Serial.print("PUT failed. Error: "); Serial.println(http.errorToString(httpResponseCode));
  }
  http.end();
}

// ---------------- SETUP ----------------
void setup() {
  Serial.begin(115200);
  pinMode(LED_PIN, OUTPUT);

  myServo.attach(SERVO_PIN);
  myServo.write(90); // STOP servo

  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);

  // ---------------- WIFI CONNECTION ----------------
  Serial.println("Connecting to WiFi...");
  WiFi.begin(ssid, password);
  unsigned long startAttemptTime = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - startAttemptTime < 15000) {
    delay(500);
    Serial.print(".");
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("\n✅ WiFi Connected!");
    Serial.print("🌐 ESP32 IP Address: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("\n⚠️ WiFi not connected. Will retry later.");
  }
}

// ---------------- LOOP ----------------
void loop() {
  // ---------- SOUND DETECTION ----------
  int soundValue = readMicAverage(SOUND_PIN);

  if (mic_on && soundValue > THRESHOLD_ON) {
    mic_on = false;
    digitalWrite(LED_PIN, HIGH);

    myServo.write(180);
    delay(OPEN_TIME);
    myServo.write(90);

    delay(OPEN_DURATION);

    myServo.write(0);
    delay(OPEN_TIME);
    myServo.write(90);

    digitalWrite(LED_PIN, LOW);
  }

  if (!mic_on && soundValue < THRESHOLD_OFF) {
    mic_on = true;
  }

  // ---------- ULTRASONIC %----------
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);

  long duration = pulseIn(ECHO_PIN, HIGH);
  float distanceCM = duration * 0.034 / 2;

  if (distanceCM > MAX_DISTANCE_CM) distanceCM = MAX_DISTANCE_CM;

  float percentFull = 100 - ((distanceCM / MAX_DISTANCE_CM) * 100);
  percentFull = constrain(percentFull, 0, 100);

  // ---------- SEND DATA TO BACKEND EVERY 1 MIN ----------
  unsigned long now = millis();
  if (now - lastPostTime >= POST_INTERVAL) {
    lastPostTime = now;

    if (WiFi.status() == WL_CONNECTED) {
      sendBinData(percentFull);
    } else {
      Serial.println("⚠️ WiFi not connected, skipping POST.");
    }
  }

  delay(100);
}
