using System.Net;
using System.Net.Mail;

namespace theseOnAuthServer.Services;

public sealed class SmtpEmailSender(IConfiguration configuration)
{
    public bool IsConfigured
    {
        get
        {
            var fromAddress = configuration["Smtp:FromAddress"];
            var portSetting = configuration["Smtp:Port"];
            var sslSetting = configuration["Smtp:EnableSsl"];
            var portIsValid = string.IsNullOrWhiteSpace(portSetting) ||
                (int.TryParse(portSetting, out var port) && port is > 0 and <= 65535);
            var sslIsValid = string.IsNullOrWhiteSpace(sslSetting) || bool.TryParse(sslSetting, out _);

            return !string.IsNullOrWhiteSpace(configuration["Smtp:Host"]) &&
                MailAddress.TryCreate(fromAddress, out _) &&
                portIsValid &&
                sslIsValid &&
                (!string.IsNullOrWhiteSpace(configuration["Smtp:Username"]) ==
                 !string.IsNullOrWhiteSpace(configuration["Smtp:Password"]));
        }
    }

    public async Task SendMagicLinkAsync(string email, string link, CancellationToken cancellationToken)
    {
        if (!IsConfigured)
        {
            throw new InvalidOperationException("SMTP settings are incomplete.");
        }

        var host = configuration["Smtp:Host"]!;
        var fromAddress = configuration["Smtp:FromAddress"]!;
        var fromName = configuration["Smtp:FromName"] ?? "theseOnAuthServer";
        var port = int.TryParse(configuration["Smtp:Port"], out var configuredPort)
            ? configuredPort
            : 587;
        var enableSsl = !bool.TryParse(configuration["Smtp:EnableSsl"], out var configuredSsl) ||
            configuredSsl;
        var username = configuration["Smtp:Username"];
        var password = configuration["Smtp:Password"];

        using var message = new MailMessage
        {
            From = new MailAddress(fromAddress, fromName),
            Subject = "Your sign-in link",
            Body = $"Use this link to sign in. It expires in 15 minutes and can only be used once:\n\n{link}",
            IsBodyHtml = false
        };
        message.To.Add(new MailAddress(email));

        using var client = new SmtpClient(host, port)
        {
            EnableSsl = enableSsl,
            Timeout = 15000
        };

        if (!string.IsNullOrWhiteSpace(username))
        {
            client.Credentials = new NetworkCredential(username, password);
        }

        cancellationToken.ThrowIfCancellationRequested();
        await client.SendMailAsync(message, cancellationToken);
    }
}
