// Libraries
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <DHT.h> //Version 2.1.3
#include <sha256.h>
#include <rBase64.h>
#include <Time.h>
#include <TimeLib.h>

// WiFi settings
const char* ssid = "ssid";
const char* password = "WiFi Password";

// Azure Log Analytics
const String CustomerId = "0438............";
const String SharedKey = "e5IL...........==";
const String LogType = "ITPC_SensorData";
const String AzureLASSLFingerPrint = "ef e8 b5 0b 72 3e 4d 08 39 7d 39 28 66 11 0e 8f fa 9d bb 10"; // Warning: will changed in April 2017

// DHT Sensor setting - from: https://learn.adafruit.com/esp8266-temperature-slash-humidity-webserver/code
#define DHTTYPE DHT22
#define DHTPIN  2
DHT dht(DHTPIN, DHTTYPE, 11);
float humidity, temp;  // Values read from sensor
unsigned long previousMillis = 0;        // will store last temp was read
const long interval = 2000;              // interval at which to read sensor

// Main program settings
const int sleepTimeS = 20;
String RFC1123DateString = "";

void setup() {
  // Init serial line
  Serial.begin(115200);
  Serial.println("ESP8266 starting");

  // Connect to WiFi
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.println("WiFi connected");

  // Print IP address
  Serial.println(WiFi.localIP());
}

void loop() {
  Serial.println();
  // Read sensor
  unsigned long currentMillis = millis();
  if (currentMillis - previousMillis >= interval)
  {
    // save the last time you read the sensor
    previousMillis = currentMillis;
    humidity = dht.readHumidity();          // Read humidity (percent)
    temp = dht.readTemperature(false);     // Read temperature as Fahrenheit
    // Check if any reads failed and exit early (to try again).
    if (isnan(humidity) || isnan(temp)) {
      Serial.println("Failed to read from DHT sensor!");
    } else
    {
      String PostData = "[{  \"SensorID\" : \"ESP8266-00000001\",  \"SensorName\" : \"Basement\",  \"DataType\" : \"Temperature\", \"DataValue\" : " + String(temp) + ", \"DataUnit\": \"Celcius\"},{   \"SensorID\" : \"ESP8266-00000001\", \"SensorName\" : \"Basement\",  \"DataType\" : \"Humidity\",  \"DataValue\" : " + String(humidity) + ", \"DataUnit\": \"RH\"}]";

      Serial.println("Upload data:");
      Serial.println(PostData);
      // Send data to cloud
      int postReturn = PostOMSData(CustomerId, SharedKey, PostData, LogType, "---", AzureLASSLFingerPrint);
    }
  }
  Serial.print("Waiting...");
  delay(sleepTimeS * 1000);
  Serial.println("Done.");
}


// Functions
String BuildSignature(String stringToHash, String sharedKey)
{
  String sharedKeyDecoded = (String)rbase64.decode(sharedKey);
  byte keyBytes[sharedKeyDecoded.length()];
  for (int i = 0; i < sharedKeyDecoded.length(); i++)
  {
    keyBytes[i] = (int)sharedKeyDecoded[i];
  }
  Sha256.init();
  Sha256.initHmac(keyBytes, sizeof(keyBytes));
  Sha256.print(stringToHash);
  uint8_t *hash;
  hash = Sha256.resultHmac();
  return (String)rbase64.encode(hash, 32);
}

int PostOMSData(String customerId, String sharedKey, String PostData, String logType, String timeGeneratedField, String fingerPrint)
{
  RFC1123DateString = GetRFC1123DateString(RFC1123DateString);
  String method = "POST";
  String contentType = "application/json";
  String resource = "/api/logs";
  String rfc1123date = RFC1123DateString;
  String xHeaders = "x-ms-date:" + rfc1123date;
  String contentLength = (String) PostData.length();
  String stringToHash = method + "\n" + contentLength + "\n" + contentType + "\n" + xHeaders + "\n" + resource;

  String signature = "SharedKey " + customerId + ":" + BuildSignature(stringToHash, sharedKey);
  String uri = "https://" + customerId + ".ods.opinsights.azure.com" + resource + "?api-version=2016-04-01";
  Serial.println("Upload data to:");
  Serial.println(uri);
  Serial.println("Upload time:");
  Serial.println(rfc1123date);

  HTTPClient http;
  http.begin(uri, fingerPrint);
  http.addHeader("Authorization", signature);
  http.addHeader("Content-Type", contentType);
  http.addHeader("Log-Type", logType);
  http.addHeader("x-ms-date", rfc1123date);
  http.addHeader("time-generated-field", timeGeneratedField);
  int returnCode = http.POST(PostData);
  if (returnCode < 0)
  {
    Serial.println("RestPostData: Error sending data to Log Analytics: " + String(http.errorToString(returnCode).c_str()));
  } else
  {
    http.end();
  }
  return returnCode;
}

void printHash(uint8_t* hash) {
  int i;
  for (i = 0; i < 32; i++) {
    Serial.print("0123456789abcdef"[hash[i] >> 4]);
    Serial.print("0123456789abcdef"[hash[i] & 0xf]);
  }
  Serial.println();
}

String GetRFC1123DateString(String LastDate)
{
  const char* host = "time.nist.gov";
  const int httpPort = 13;
  String rfc1123date = LastDate;
  tmElements_t tm;
  time_t t;

  String TimeDate = "";
  WiFiClient client;
  if (!client.connect(host, httpPort)) {
    Serial.println("Error: GetRFC1123DateString - Connection failed!");
    return rfc1123date;
  }
  client.print("HEAD / HTTP/1.1\r\nAccept: */*\r\nUser-Agent: Mozilla/4.0 (compatible; ESP8266 NodeMcu Lua;)\r\n\r\n");
  char buffer[12];
  String dateTime = "";

  // Wait for client
  unsigned long cMilliS = millis();
  unsigned long lMilliS = cMilliS;
  while (!client.available() and ((cMilliS - lMilliS) < 5000)) {
    delay(80);
    Serial.print("=");
    cMilliS = millis();
  }
  while (client.available())
  {
    String line = client.readStringUntil('\r');
    if (line.indexOf("Date") != -1)
    {
      Serial.print("=====>");
    } else
    {
      TimeDate = line.substring(7);
      char buf[3];
      line.substring(13, 15).toCharArray(buf, sizeof(buf));
      tm.Day = atoi(buf);
      line.substring(10, 12).toCharArray(buf, sizeof(buf));
      tm.Month = atoi(buf);
      line.substring(7, 9).toCharArray(buf, sizeof(buf));
      tm.Year = atoi(buf) + 2000 - 1970;
      line.substring(16, 18).toCharArray(buf, sizeof(buf));
      tm.Hour = atoi(buf);
      line.substring(19, 21).toCharArray(buf, sizeof(buf));
      tm.Minute = atoi(buf);
      line.substring(22, 24).toCharArray(buf, sizeof(buf));
      tm.Second = atoi(buf);
      String timeUTC = line.substring(16, 24);
      t = makeTime(tm);
      rfc1123date = dayShortStr(weekday(t));
      rfc1123date += ", ";
      rfc1123date += line.substring(13, 15) + " ";
      rfc1123date += monthShortStr(month(t));
      rfc1123date += " 20" + line.substring(7, 9) + " ";
      rfc1123date += timeUTC + " GMT";
      if (rfc1123date == LastDate)
      {
        Serial.println("Error: GetRFC1123DateString - Unable to get date!");
      }
    }
  }
  client.stop();
  return rfc1123date;
}

