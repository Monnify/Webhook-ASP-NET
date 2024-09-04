using Microsoft.AspNetCore.Mvc;
using System.Text;
using System.Text.Json;

namespace MonnifyWebhook.Api.Controllers
{
   
    [Route("api/[controller]")]
    [ApiController]
    public class WebhookController : ControllerBase
    {
        private readonly ILogger<WebhookController> _logger;
        public WebhookController(ILogger<WebhookController> logger)
        {
            _logger = logger;
        }

        [HttpPost("receive")]
        public async Task<IActionResult> ReceiveWebhook()
        {
            using var reader = new StreamReader(Request.Body);
            var payload = await reader.ReadToEndAsync();
            //_logger.LogInformation($"Received webhook payload: {payload}");

            var receivedSignature = Request.Headers["monnify-signature"].FirstOrDefault();
            var secretKey = "YOUR-MONNIFY-SECRET-KEY";
            Console.WriteLine($"THIS IS THE MONNIFY HASH: {receivedSignature}");

            if (!IsSignatureValid(payload, receivedSignature, secretKey))
            {
                _logger.LogWarning("Invalid signature for webhook");
                return Unauthorized("Webhook hash validation failed");
            }

            try
            {
                var jsonData = JsonSerializer.Deserialize<dynamic>(payload);
                //_logger.LogInformation($"Decoded webhook: {jsonData}");
                _logger.LogInformation("Webhook hash match successful");
                return Ok("Webhook hash match successful");
            }
            catch(JsonException ex)
            {
                _logger.LogError($"Error decoding webhook payload: {ex.Message}");
                return BadRequest("Invalid payload format");
            }
        }

        private bool IsSignatureValid(string payload, string receivedSignature, string secretKey)
        {
            using var hmac = new System.Security.Cryptography.HMACSHA512(Encoding.UTF8.GetBytes(secretKey));
            var hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            
            var calculatedSignature = BitConverter.ToString(hash).Replace("-", "").ToLower();
            Console.WriteLine($"THIS IS THE COMPUTED HASH {calculatedSignature}");
            return calculatedSignature.Equals(receivedSignature);
        }
    }


}
