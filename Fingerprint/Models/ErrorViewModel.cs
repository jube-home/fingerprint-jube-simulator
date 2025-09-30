namespace Fingerprint.Models;

public class ErrorViewModel
{
    // ReSharper disable once PropertyCanBeMadeInitOnly.Global
    public string? RequestId { get; set; }

    public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
}