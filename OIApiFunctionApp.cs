using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Net;
using System.Xml.Linq;

namespace OIApiFunctionApp
{
    public static class OIApiFunctionApp
    {
        // An example JSON object, with key/value pairs
        //static string json = @"[{""DemoField1"":""DemoValue1"",""DemoField2"":""DemoValue2""},{""DemoField3"":""DemoValue3"",""DemoField4"":""DemoValue4""}]";

        // Update customerId to your Log Analytics workspace ID
        //static string customerId = "";

        // For sharedKey, use either the primary or the secondary Connected Sources client authentication key   
        //static string sharedKey = "";

        // LogName is name of the event type that is being submitted to Azure Monitor
        //static string LogName = "DemoExample";

        // You can use an optional field to specify the timestamp from the data. If the time field is not specified, Azure Monitor assumes the time is the message ingestion time
        static string TimeStampField = "";

        [FunctionName("OIApiFunctionApp")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string customerId = req.Query["customerId"];
            log.LogInformation(customerId);
            string sharedKey = req.Query["sharedKey"];
            log.LogInformation(sharedKey);
            string logName = req.Query["logName"];
            log.LogInformation(logName);
            //string name = req.Query["name"];
            //log.LogInformation(name);

            //read json object from request body
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            log.LogInformation(requestBody);
            //dynamic data = JsonConvert.DeserializeObject(requestBody);
            //name = name ?? data?.name;

            // Create a hash for the API signature
            var datestring = DateTime.UtcNow.ToString("r");
            log.LogInformation(datestring);
            var jsonBytes = Encoding.UTF8.GetBytes(requestBody);
            
            string stringToHash = "POST\n" + jsonBytes.Length + "\napplication/json\n" + "x-ms-date:" + datestring + "\n/api/logs";
            log.LogInformation(stringToHash);
            string hashedString = BuildSignature(stringToHash, sharedKey, log);
            string signature = "SharedKey " + customerId + ":" + hashedString;

            string postDataResult = PostData(signature, datestring, requestBody, customerId, logName);
            string responseMessage = string.IsNullOrEmpty(postDataResult)
                ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                : $"Hello, {postDataResult}. This HTTP triggered function executed successfully.";

            return new OkObjectResult(responseMessage);

        }

        public static byte[] DecodeUrlBase64(string s)
        {
            s = s.Replace(' ', '+').Replace('-', '+').Replace('_', '/').PadRight(4 * ((s.Length + 3) / 4), '=');
            return Convert.FromBase64String(s);
        }

        // Build the API signature
        public static string BuildSignature(string message, string secret, ILogger log)
        {
            log.LogInformation($"{secret}");
            var encoding = new System.Text.ASCIIEncoding();
            log.LogInformation(encoding.ToString());
            byte[] keyByte = DecodeUrlBase64(secret);
            log.LogInformation(keyByte.ToString());
            byte[] messageBytes = encoding.GetBytes(message);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                byte[] hash = hmacsha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(hash);
            }
        }

        // Send a request to the POST API endpoint
        public static string PostData(string signature, string date, string json, string customerId, string logName)
        {
            string postDataResult = "";
            try
            {
                string url = "https://" + customerId + ".ods.opinsights.azure.com/api/logs?api-version=2016-04-01";

                System.Net.Http.HttpClient client = new System.Net.Http.HttpClient();
                client.DefaultRequestHeaders.Add("Accept", "application/json");
                client.DefaultRequestHeaders.Add("Log-Type", logName);
                client.DefaultRequestHeaders.Add("Authorization", signature);
                client.DefaultRequestHeaders.Add("x-ms-date", date);
                client.DefaultRequestHeaders.Add("time-generated-field", TimeStampField);

                // If charset=utf-8 is part of the content-type header, the API call may return forbidden.
                System.Net.Http.HttpContent httpContent = new StringContent(json, Encoding.UTF8);
                httpContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
                Task<System.Net.Http.HttpResponseMessage> response = client.PostAsync(new Uri(url), httpContent);

                System.Net.Http.HttpContent responseContent = response.Result.Content;
                string result = responseContent.ReadAsStringAsync().Result;
                Console.WriteLine("Return Result: " + result);
            }
            catch (Exception excep)
            {
                Console.WriteLine("API Post Exception: " + excep.Message);
            }
            return postDataResult;
        }
    }
}
