namespace Fingerprint.Models;

public class Request
{
    public string? AccountId { get; set; }
    public string? CreditCardHash { get; set; }
    public string? Email { get; set; }
    public string? BillingFirstName { get; set; }
    public string? BillingLastName { get; set; }
    public float? CurrencyAmount { get; set; }
    public string? FingerprintRequestId { get; set; }
}