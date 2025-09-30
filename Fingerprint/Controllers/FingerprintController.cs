using System.Text;
using FingerprintPro.ServerSdk.Api;
using FingerprintPro.ServerSdk.Client;
using FingerprintPro.ServerSdk.Model;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using JsonSerializer = System.Text.Json.JsonSerializer;
using FingerprintRequest = Fingerprint.Models.Request;
using JubeRequest = Fingerprint.Models.Jube.Request;
using JubeResponse = Fingerprint.Models.Jube.Response;
using FingerprintResponse = Fingerprint.Models.Response;

namespace Fingerprint.Controllers;

[Route("api/[controller]")]
[ApiController]
public class FingerprintController : Controller
{
    [HttpPost]
    public async Task<ActionResult<FingerprintResponse>> Post(FingerprintRequest model)
    {
        if (model.FingerprintRequestId == null) return BadRequest();

        var responseFromJube = await FetchFingerprintDataAndInvokeJube(model);

        return new FingerprintResponse
        {
            Value = responseFromJube?.ResponseElevation.Value,
            Content = responseFromJube?.ResponseElevation.Content
        };
    }

    private async Task<JubeResponse?> FetchFingerprintDataAndInvokeJube(FingerprintRequest model)
    {
        var jubePayload = await CreateJubePayloadWithFingerprintAndTransactionData(model);
        return await InvokeJube(jubePayload);
    }

    private static async Task<JubeResponse?> InvokeJube(JubeRequest payload)
    {
        var httpClient = new HttpClient();

        using StringContent jsonContent = new(
            JsonSerializer.Serialize(payload),
            Encoding.UTF8,
            "application/json");

        var responseString = await httpClient.PostAsync(
            "http://127.0.0.1:5001/api/invoke/EntityAnalysisModel/90c425fd-101a-420b-91d1-cb7a24a969cc",
            jsonContent).Result.Content.ReadAsStringAsync();

        return JsonConvert.DeserializeObject<JubeResponse>(responseString);
    }

    private async Task<JubeRequest> CreateJubePayloadWithFingerprintAndTransactionData(FingerprintRequest model)
    {
        var jubeRequest = new JubeRequest();
        CreateTransactionData(model, jubeRequest);

        var fingerprintApiResponse = await InvokeFingerprintApi(model);
        ParseIdentification(jubeRequest, fingerprintApiResponse);
        ParseIpInfo(jubeRequest, fingerprintApiResponse);
        ParseFingerprint(jubeRequest, fingerprintApiResponse);
        ParseRootApps(jubeRequest, fingerprintApiResponse);
        ParseEmulator(jubeRequest, fingerprintApiResponse);
        ParseIpBlocklist(jubeRequest, fingerprintApiResponse);
        ParseTor(jubeRequest, fingerprintApiResponse);
        ParseVpn(jubeRequest, fingerprintApiResponse);
        ParseProxy(jubeRequest, fingerprintApiResponse);
        ParseIncognito(jubeRequest, fingerprintApiResponse);
        ParseTampering(jubeRequest, fingerprintApiResponse);
        ParseClonedApp(jubeRequest, fingerprintApiResponse);
        ParseFactoryReset(jubeRequest, fingerprintApiResponse);
        ParseJailbroken(jubeRequest, fingerprintApiResponse);
        ParseFrida(jubeRequest, fingerprintApiResponse);
        ParsePrivacySettings(jubeRequest, fingerprintApiResponse);
        ParseVirtualMachine(jubeRequest, fingerprintApiResponse);
        ParseHighActivity(jubeRequest, fingerprintApiResponse);
        ParseDeveloperTools(jubeRequest, fingerprintApiResponse);
        ParseMitm(jubeRequest, fingerprintApiResponse);

        return jubeRequest;
    }

    private static async Task<EventsGetResponse?> InvokeFingerprintApi(FingerprintRequest model)
    {
        var configuration = new Configuration(Environment.GetEnvironmentVariable("FINGERPRINT_API_KEY"))
        {
            Region = Region.Eu
        };

        var api = new FingerprintApi(
            configuration
        );

        if (model.FingerprintRequestId == null) return null;

        var events = await api.GetEventAsync(model.FingerprintRequestId);
        return events;
    }

    private void CreateTransactionData(FingerprintRequest model, JubeRequest request)
    {
        try
        {
            request.AccountId = model.AccountId;
            request.TxnId = Guid.NewGuid().ToString("N");
            request.CurrencyAmount = model.CurrencyAmount;
            request.IP = HttpContext.Connection.RemoteIpAddress?.ToString();
            request.TxnDateTime = DateTime.Now.ToString("O");
            request.BillingFirstName = model.BillingFirstName;
            request.BillingLastName = model.BillingLastName;
            request.Email = model.Email;
            request.CreditCardHash = model.CreditCardHash;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseMitm(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintMitmAttack = events?.Products.MitmAttack.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseDeveloperTools(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintDeveloperTools = events?.Products.DeveloperTools.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseHighActivity(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintHighActivity = events?.Products.HighActivity.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseVirtualMachine(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintVirtualMachine = events?.Products.VirtualMachine.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParsePrivacySettings(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintPrivacySettings = events?.Products.PrivacySettings.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseFrida(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintFrida = events?.Products.Frida.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseJailbroken(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintJailbroken = events?.Products.Jailbroken.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseFactoryReset(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintFactoryResetTime = events?.Products.FactoryReset.Data.Time.ToString();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseClonedApp(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintClonedApp = events?.Products.ClonedApp.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseTampering(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintTampering = events?.Products.Tampering.Data.Result;
            request.FingerprintTamperingAnomalyScore = events?.Products.Tampering.Data.AnomalyScore;
            request.FingerprintTamperingAntiDetectBrowser = events?.Products.Tampering.Data.AntiDetectBrowser;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseIncognito(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintIncognito = events?.Products.Incognito.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseProxy(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            if (events == null) return;

            request.FingerprintProxy = events.Products.Proxy.Data.Result;
            request.FingerprintProxyConfidence = (int)events.Products.Proxy.Data.Confidence;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseVpn(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            if (events == null) return;

            request.FingerprintVpn = events.Products.Vpn.Data.Result;
            request.FingerprintVpnConfidence = (int)events.Products.Vpn.Data.Confidence;
            request.FingerprintVpnOriginTimezone = events.Products.Vpn.Data.OriginTimezone;
            request.FingerprintVpnOriginCountry = events.Products.Vpn.Data.OriginCountry;
            request.FingerprintVpnOriginMethodsTimezoneMismatch = events.Products.Vpn.Data.Methods.TimezoneMismatch;
            request.FingerprintVpnOriginMethodsPublicVpn = events.Products.Vpn.Data.Methods.PublicVPN;
            request.FingerprintVpnOriginMethodsAuxiliaryMobile = events.Products.Vpn.Data.Methods.AuxiliaryMobile;
            request.FingerprintVpnOriginMethodsOsMismatch = events.Products.Vpn.Data.Methods.OsMismatch;
            request.FingerprintVpnOriginMethodsRelay = events.Products.Vpn.Data.Methods.Relay;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseTor(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintTor = events?.Products.Tor.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseIpBlocklist(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            if (events == null) return;

            request.FingerprintIpBlocklist = events.Products.IpBlocklist.Data.Result;
            request.FingerprintIpBlocklistDetailsEmailSpam = events.Products.IpBlocklist.Data.Details.EmailSpam;
            request.FingerprintIpBlocklistDetailsAttackSource =
                events.Products.IpBlocklist.Data.Details.AttackSource;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseEmulator(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintEmulator = events?.Products.Emulator.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseRootApps(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            request.FingerprintRootApps = events?.Products.RootApps.Data.Result;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseFingerprint(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            if (events == null) return;

            request.FingerprintBot = (int)events.Products.Botd.Data.Bot.Result;
            request.FingerprintBotUrl = events.Products.Botd.Data.Url;
            request.FingerprintBotIp = events.Products.Botd.Data.Ip;
            request.FingerprintBotTime = events.Products.Botd.Data.Time.ToString();
            request.FingerprintBotUserAgent = events.Products.Botd.Data.UserAgent;
            request.FingerprintBotRequestId = events.Products.Botd.Data.RequestId;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseIpInfo(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            if (events == null) return;

            request.FingerprintIpInfoAddress = events.Products.IpInfo.Data.V4.Address;
            request.FingerprintIpInfoIpLatitude = events.Products.IpInfo.Data.V4.Geolocation.Latitude;
            request.FingerprintIpInfoLongitude = events.Products.IpInfo.Data.V4.Geolocation.Longitude;
            request.FingerprintIpInfoTimezone = events.Products.IpInfo.Data.V4.Geolocation.Timezone;
            request.FingerprintIpInfoCity = events.Products.IpInfo.Data.V4.Geolocation.City.Name;
            request.FingerprintIpInfoCountryCode =
                events.Products.IpInfo.Data.V4.Geolocation.Country.Code;
            request.FingerprintIpInfoCountryName =
                events.Products.IpInfo.Data.V4.Geolocation.Country.Name;
            request.FingerprintIpInfoContinentCode =
                events.Products.IpInfo.Data.V4.Geolocation.Continent.Code;
            request.FingerprintIpInfoContinentName =
                events.Products.IpInfo.Data.V4.Geolocation.Continent.Name;
            request.FingerprintIpInfoPostalCode = events.Products.IpInfo.Data.V4.Geolocation.PostalCode;
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    private static void ParseIdentification(JubeRequest request, EventsGetResponse? events)
    {
        try
        {
            if (events == null) return;

            request.FingerprintIdentificationVisitorId = events.Products.Identification.Data.VisitorId;
            request.FingerprintIdentificationRequestId = events.Products.Identification.Data.RequestId;
            request.FingerprintIdentificationBrowserDetailsBrowserName =
                events.Products.Identification.Data.BrowserDetails.BrowserName;
            request.FingerprintIdentificationBrowserMajorVersion =
                events.Products.Identification.Data.BrowserDetails.BrowserMajorVersion;
            request.FingerprintIdentificationBrowserFullVersion =
                events.Products.Identification.Data.BrowserDetails.BrowserFullVersion;
            request.FingerprintIdentificationBrowserOs = events.Products.Identification.Data.BrowserDetails.Os;
            request.FingerprintIdentificationBrowserOsVersion =
                events.Products.Identification.Data.BrowserDetails.OsVersion;
            request.FingerprintIdentificationBrowserDevice =
                events.Products.Identification.Data.BrowserDetails.Device;
            request.FingerprintIdentificationConfidenceScore = events.Products.Identification.Data.Confidence.Score;
            request.FingerprintIdentificationVisitorFound = events.Products.Identification.Data.VisitorFound;
            request.FingerprintIdentificationReplayed = events.Products.Identification.Data.Replayed;
            request.FingerprintIdentificationFirstSeenAtGlobal =
                events.Products.Identification.Data.FirstSeenAt.Global.ToString();
            request.FingerprintIdentificationFirstSeenAtSubscription =
                events.Products.Identification.Data.FirstSeenAt.Subscription.ToString();
            request.FingerprintIdentificationLastSeenAtGlobal =
                events.Products.Identification.Data.LastSeenAt.Global.ToString();
            request.FingerprintIdentificationLastSeenAtSubscription =
                events.Products.Identification.Data.LastSeenAt.Subscription.ToString();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }
}