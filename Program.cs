using System.Net.Mail;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using theseOnAuthServer.Data;
using theseOnAuthServer.Models;
using theseOnAuthServer.Services;

var builder = WebApplication.CreateBuilder(args);

string client_id = builder.Configuration["secret:client_id"] ?? "";
string spa_client_id = builder.Configuration["secret:client_id"] ?? "";
var spaRedirectUris = builder.Configuration
    .GetSection("OpenIddict:Spa:RedirectUris")
    .Get<string[]>();
var spaLoginUrl = builder.Configuration["OpenIddict:Spa:LoginUrl"];
bool isDevelopment = builder.Environment.IsDevelopment();

if (string.IsNullOrWhiteSpace(client_id) &&
    isDevelopment)
    client_id = "theseOnAuthServer";

if (string.IsNullOrWhiteSpace(spa_client_id) &&
    isDevelopment)
    spa_client_id = "theseOnOAuth";

if (spaRedirectUris is null || spaRedirectUris.Length == 0)
{
    if (!isDevelopment)
    {
        throw new InvalidOperationException(
            "Configure OpenIddict:Spa:RedirectUris with the SPA's exact HTTPS callback URLs.");
    }

    spaRedirectUris =
    [
        "http://localhost:5173/auth/callback",
        "http://127.0.0.1:5173/auth/callback"
    ];
}

if (string.IsNullOrWhiteSpace(spaLoginUrl) &&
    isDevelopment)
{
    spaLoginUrl = "http://localhost:5173/account/login";
}

if (!Uri.TryCreate(spaLoginUrl, UriKind.Absolute, out var spaLoginUri) ||
    !string.IsNullOrEmpty(spaLoginUri.UserInfo) ||
    !string.IsNullOrEmpty(spaLoginUri.Query) ||
    !string.IsNullOrEmpty(spaLoginUri.Fragment) ||
    (spaLoginUri.Scheme != Uri.UriSchemeHttps &&
     !(isDevelopment &&
       spaLoginUri.Scheme == Uri.UriSchemeHttp &&
       (spaLoginUri.IsLoopback || spaLoginUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase)))))
{
    throw new InvalidOperationException(
        "Configure OpenIddict:Spa:LoginUrl with an HTTPS SPA login URL. HTTP is only allowed for loopback development URLs.");
}

if (spaRedirectUris.Any(uri =>
        !Uri.TryCreate(uri, UriKind.Absolute, out var redirectUri) ||
        (redirectUri.Scheme != Uri.UriSchemeHttps &&
         !(isDevelopment &&
           redirectUri.Scheme == Uri.UriSchemeHttp &&
           (redirectUri.IsLoopback || redirectUri.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase))))))
{
    throw new InvalidOperationException(
        "SPA redirect URIs must use HTTPS. HTTP is only allowed for loopback development URLs.");
}

var spaOrigins = spaRedirectUris
    .Select(uri => new Uri(uri).GetLeftPart(UriPartial.Authority))
    .Append(spaLoginUri.GetLeftPart(UriPartial.Authority))
    .Distinct(StringComparer.OrdinalIgnoreCase)
    .ToArray();

builder.Services.AddCors(options =>
{
    options.AddPolicy("Spa", policy =>
    {
        policy.WithOrigins(spaOrigins)
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});
builder.Services.AddOpenApi();
builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = $"__Host-{client_id}";
        options.Cookie.HttpOnly = true;
        options.Cookie.Path = "/";
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(8);
        options.SlidingExpiration = true;
    });
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    // if (isDevelopment)
    // {
    options.UseInMemoryDatabase("auth");
    // }

    options.UseOpenIddict();
});
builder.Services.AddAuthorization();
builder.Services.AddSingleton<IPasswordHasher<AuthUser>, PasswordHasher<AuthUser>>();
builder.Services.AddSingleton<SmtpEmailSender>();

X509Certificate2? productionCertificate = null;
if (!isDevelopment)
{
    var certificatePath = builder.Configuration["OpenIddict:CertificatePath"];
    if (string.IsNullOrWhiteSpace(certificatePath))
    {
        throw new InvalidOperationException(
            "Configure OpenIddict:CertificatePath with a PFX certificate path before running outside Development.");
    }

    productionCertificate = X509CertificateLoader.LoadPkcs12FromFile(
        certificatePath,
        builder.Configuration["OpenIddict:CertificatePassword"]);
}

builder.Services.AddOpenIddict()
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
            .UseDbContext<AuthDbContext>();
    })
    .AddServer(options =>
    {
        options.SetAuthorizationEndpointUris("/connect/authorize")
            .SetTokenEndpointUris("/connect/token")
            .AllowAuthorizationCodeFlow()
            .RequireProofKeyForCodeExchange()
            .AllowPasswordFlow()
            .AllowCustomFlow(AuthConstants.MagicLinkGrantType)
            .RegisterScopes(
                OpenIddictConstants.Scopes.OpenId,
                OpenIddictConstants.Scopes.Profile,
                OpenIddictConstants.Scopes.Email)
            .SetAccessTokenLifetime(TimeSpan.FromMinutes(15));

        options.UseAspNetCore()
            .EnableAuthorizationEndpointPassthrough()
            .EnableTokenEndpointPassthrough();

        if (productionCertificate is null)
        {
            options.AddDevelopmentEncryptionCertificate()
                .AddDevelopmentSigningCertificate();
        }
        else
        {
            options.AddEncryptionCertificate(productionCertificate)
                .AddSigningCertificate(productionCertificate);
        }
    });

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var database = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    await database.Database.EnsureCreatedAsync();

    var applicationManager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
    if (await applicationManager.FindByClientIdAsync(client_id) is null)
    {
        var application = new OpenIddictApplicationDescriptor
        {
            ClientId = client_id,
            ClientType = OpenIddictConstants.ClientTypes.Public,
            DisplayName = $"{client_id} first-party client"
        };
        application.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        application.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
        application.Permissions.Add(
            OpenIddictConstants.Permissions.Prefixes.GrantType + AuthConstants.MagicLinkGrantType);
        application.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);
        application.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
        await applicationManager.CreateAsync(application);
    }

    var spaApplication = new OpenIddictApplicationDescriptor
    {
        ClientId = spa_client_id,
        ClientType = OpenIddictConstants.ClientTypes.Public,
        DisplayName = "Auth SPA"
    };
    spaApplication.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Authorization);
    spaApplication.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
    spaApplication.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
    spaApplication.Permissions.Add(OpenIddictConstants.Permissions.ResponseTypes.Code);
    spaApplication.Permissions.Add(
        OpenIddictConstants.Permissions.Prefixes.Scope + OpenIddictConstants.Scopes.OpenId);
    spaApplication.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);
    spaApplication.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Email);
    foreach (var redirectUri in spaRedirectUris)
    {
        spaApplication.RedirectUris.Add(new Uri(redirectUri));
    }

    var existingSpaApplication = await applicationManager.FindByClientIdAsync(spa_client_id);
    if (existingSpaApplication is null)
    {
        await applicationManager.CreateAsync(spaApplication);
    }
    else
    {
        await applicationManager.UpdateAsync(existingSpaApplication, spaApplication);
    }
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}
app.UseCors("Spa");

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", RegisterAsync).AllowAnonymous();
app.MapPost("/auth/magic-link", SendMagicLinkAsync).AllowAnonymous();
app.MapGet("/connect/authorize", AuthorizeAsync).AllowAnonymous();
app.MapPost("/account/login", PostLoginAsync).AllowAnonymous();
app.MapPost("/connect/token", LoginAsync).AllowAnonymous();

app.Run();

static async Task<IResult> AuthorizeAsync(
    HttpContext context,
    AuthDbContext database,
    IConfiguration configuration)
{
    var request = context.GetOpenIddictServerRequest()
        ?? throw new InvalidOperationException("The OpenIddict authorization request could not be retrieved.");
    var returnUrl = context.Request.PathBase + context.Request.Path + context.Request.QueryString;
    var authentication = await context.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    var forceLogin = request.GetParameter("prompt")?.ToString()?
        .Split(' ', StringSplitOptions.RemoveEmptyEntries)
        .Contains("login", StringComparer.Ordinal) ?? false;

    if (!authentication.Succeeded || forceLogin)
    {
        var promptNone = request.GetParameter("prompt")?.ToString()?
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Contains("none", StringComparer.Ordinal) ?? false;
        if (promptNone)
        {
            return ForbidOpenIddict(OpenIddictConstants.Errors.LoginRequired);
        }

        var loginChallenge = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var now = DateTimeOffset.UtcNow;
        var staleChallenges = await database.LoginChallenges
            .Where(challenge => challenge.ExpiresAt <= now || challenge.ConsumedAt != null)
            .ToListAsync();
        database.LoginChallenges.RemoveRange(staleChallenges);
        database.LoginChallenges.Add(new LoginChallenge
        {
            Id = Guid.NewGuid(),
            ChallengeHash = HashMagicLinkToken(loginChallenge),
            ReturnUrl = returnUrl,
            ExpiresAt = now.AddMinutes(10)
        });
        await database.SaveChangesAsync();

        var loginUrl = QueryHelpers.AddQueryString(
            configuration["OpenIddict:Spa:LoginUrl"]!,
            new Dictionary<string, string?>
            {
                ["returnUrl"] = returnUrl,
                ["loginChallenge"] = loginChallenge
            });
        return Results.Redirect(loginUrl);
    }

    var subject = authentication.Principal?.FindFirstValue(ClaimTypes.NameIdentifier);
    if (!Guid.TryParse(subject, out var userId))
    {
        return ForbidOpenIddict(OpenIddictConstants.Errors.LoginRequired);
    }

    var user = await database.Users.SingleOrDefaultAsync(candidate => candidate.Id == userId);
    if (user is null)
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return ForbidOpenIddict(OpenIddictConstants.Errors.LoginRequired);
    }

    var principal = CreatePrincipal(user, request.GetScopes());
    return Results.SignIn(
        principal,
        authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}

static async Task<IResult> PostLoginAsync(
    HttpContext context,
    AuthDbContext database,
    IPasswordHasher<AuthUser> passwordHasher,
    IConfiguration configuration,
    CancellationToken cancellationToken)
{
    var loginUrl = configuration["OpenIddict:Spa:LoginUrl"]!;
    if (!context.Request.HasFormContentType ||
        !HasValidSpaOrigin(context.Request.Headers.Origin.ToString(), loginUrl))
    {
        return Results.BadRequest(new { error = "invalid_login_request" });
    }

    var form = await context.Request.ReadFormAsync(cancellationToken);
    var returnUrl = form["returnUrl"].ToString();
    var rawChallenge = form["loginChallenge"].ToString();
    if (!IsLocalReturnUrl(returnUrl) || string.IsNullOrWhiteSpace(rawChallenge))
    {
        return Results.BadRequest(new { error = "invalid_login_request" });
    }

    var challengeHash = HashMagicLinkToken(rawChallenge);
    var challenge = await database.LoginChallenges.SingleOrDefaultAsync(
        candidate => candidate.ChallengeHash == challengeHash,
        cancellationToken);
    var now = DateTimeOffset.UtcNow;
    if (challenge is null ||
        challenge.ConsumedAt is not null ||
        challenge.ExpiresAt <= now ||
        !string.Equals(challenge.ReturnUrl, returnUrl, StringComparison.Ordinal))
    {
        return Results.BadRequest(new { error = "login_challenge_expired" });
    }

    var identifier = form["identifier"].ToString().Trim();
    var normalizedIdentifier = identifier.ToUpperInvariant();
    var user = string.IsNullOrWhiteSpace(identifier)
        ? null
        : await database.Users.SingleOrDefaultAsync(candidate =>
            candidate.NormalizedUsername == normalizedIdentifier ||
            candidate.NormalizedEmail == normalizedIdentifier,
            cancellationToken);
    var password = form["password"].ToString();

    if (user is null ||
        passwordHasher.VerifyHashedPassword(user, user.PasswordHash, password) ==
        PasswordVerificationResult.Failed)
    {
        var retryUrl = QueryHelpers.AddQueryString(
            loginUrl,
            new Dictionary<string, string?>
            {
                ["returnUrl"] = returnUrl,
                ["loginChallenge"] = rawChallenge,
                ["error"] = "invalid_credentials"
            });
        return Results.Redirect(retryUrl);
    }

    challenge.ConsumedAt = now;
    try
    {
        await database.SaveChangesAsync(cancellationToken);
    }
    catch (DbUpdateConcurrencyException)
    {
        return Results.BadRequest(new { error = "login_challenge_expired" });
    }

    var identity = new ClaimsIdentity(CookieAuthenticationDefaults.AuthenticationScheme);
    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()));
    identity.AddClaim(new Claim(ClaimTypes.Name, user.Username));
    await context.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(identity));

    return Results.LocalRedirect(returnUrl);
}

static bool IsLocalReturnUrl(string? returnUrl) =>
    !string.IsNullOrEmpty(returnUrl) &&
    returnUrl[0] == '/' &&
    (returnUrl.Length == 1 || (returnUrl[1] != '/' && returnUrl[1] != '\\')) &&
    !returnUrl.Contains('\r') &&
    !returnUrl.Contains('\n');

static bool HasValidSpaOrigin(string? origin, string spaLoginUrl)
{
    if (!Uri.TryCreate(origin, UriKind.Absolute, out var originUri))
    {
        return false;
    }

    var expectedOrigin = new Uri(spaLoginUrl).GetLeftPart(UriPartial.Authority);
    return originUri.AbsolutePath == "/" &&
        string.IsNullOrEmpty(originUri.Query) &&
        string.IsNullOrEmpty(originUri.Fragment) &&
        string.Equals(
            originUri.GetLeftPart(UriPartial.Authority),
            expectedOrigin,
            StringComparison.OrdinalIgnoreCase);
}

static IResult ForbidOpenIddict(string error)
{
    var properties = new AuthenticationProperties(new Dictionary<string, string?>
    {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = error
    });
    return Results.Forbid(properties, [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme]);
}

static async Task<IResult> RegisterAsync(
    RegisterRequest request,
    AuthDbContext database,
    IPasswordHasher<AuthUser> passwordHasher)
{
    var username = request.Username?.Trim();
    if (string.IsNullOrWhiteSpace(username) || username.Length is < 3 or > 64 ||
        username.Any(char.IsWhiteSpace))
    {
        return Results.BadRequest(new
        {
            error = "invalid_username",
            message = "Username must be 3-64 characters with no whitespace."
        });
    }

    if (!TryNormalizeEmail(request.Email, out var email, out var normalizedEmail))
    {
        return Results.BadRequest(new { error = "invalid_email", message = "A valid email address is required." });
    }

    if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length is < 12 or > 256)
    {
        return Results.BadRequest(new { error = "invalid_password", message = "Password must be 12-256 characters." });
    }

    var normalizedUsername = username.ToUpperInvariant();
    if (await database.Users.AnyAsync(user =>
            user.NormalizedUsername == normalizedUsername ||
            user.NormalizedEmail == normalizedEmail ||
            user.NormalizedUsername == normalizedEmail ||
            user.NormalizedEmail == normalizedUsername))
    {
        return Results.Conflict(new { error = "account_identifier_taken" });
    }

    var user = new AuthUser
    {
        Id = Guid.NewGuid(),
        Username = username,
        NormalizedUsername = normalizedUsername,
        Email = email,
        NormalizedEmail = normalizedEmail
    };
    user.PasswordHash = passwordHasher.HashPassword(user, request.Password);

    database.Users.Add(user);
    await database.SaveChangesAsync();

    return Results.Json(
        new { user.Id, user.Username, user.Email },
        statusCode: StatusCodes.Status201Created);
}

static async Task<IResult> SendMagicLinkAsync(
    MagicLinkRequest request,
    AuthDbContext database,
    SmtpEmailSender emailSender,
    IConfiguration configuration,
    IWebHostEnvironment environment,
    ILoggerFactory loggerFactory,
    CancellationToken cancellationToken)
{
    if (!TryNormalizeEmail(request.Email, out var email, out var normalizedEmail))
    {
        return Results.BadRequest(new { error = "invalid_email", message = "A valid email address is required." });
    }

    var callbackUrl = configuration["MagicLinks:CallbackUrl"];
    if (!emailSender.IsConfigured ||
        !Uri.TryCreate(callbackUrl, UriKind.Absolute, out var callbackUri) ||
        !string.IsNullOrEmpty(callbackUri.UserInfo) ||
        !string.IsNullOrEmpty(callbackUri.Fragment) ||
        (callbackUri.Scheme != Uri.UriSchemeHttps &&
         (callbackUri.Scheme != Uri.UriSchemeHttp || !environment.IsDevelopment())))
    {
        return Results.Problem(
            statusCode: StatusCodes.Status503ServiceUnavailable,
            title: "Magic-link sign-in is not configured.");
    }

    var user = await database.Users.SingleOrDefaultAsync(
        candidate => candidate.NormalizedEmail == normalizedEmail,
        cancellationToken);

    if (user is not null)
    {
        var now = DateTimeOffset.UtcNow;
        var activeTokens = await database.MagicLinkTokens
            .Where(token => token.AuthUserId == user.Id && token.ConsumedAt == null)
            .ToListAsync(cancellationToken);

        foreach (var activeToken in activeTokens)
        {
            activeToken.ConsumedAt = now;
        }

        var rawToken = WebEncoders.Base64UrlEncode(RandomNumberGenerator.GetBytes(32));
        var tokenHash = HashMagicLinkToken(rawToken);
        database.MagicLinkTokens.Add(new MagicLinkToken
        {
            Id = Guid.NewGuid(),
            AuthUserId = user.Id,
            TokenHash = tokenHash,
            ExpiresAt = now.AddMinutes(15)
        });
        await database.SaveChangesAsync(cancellationToken);

        var link = QueryHelpers.AddQueryString(callbackUri.ToString(), "token", rawToken);
        try
        {
            await emailSender.SendMagicLinkAsync(email, link, cancellationToken);
        }
        catch (Exception exception) when (exception is SmtpException or InvalidOperationException)
        {
            loggerFactory.CreateLogger("MagicLink").LogError(
                exception,
                "Could not send an email sign-in link.");
        }
    }

    return Results.Accepted(value: new
    {
        message = "If an account exists for that email, a sign-in link has been sent."
    });
}

static async Task<IResult> LoginAsync(
    HttpContext context,
    AuthDbContext database,
    IPasswordHasher<AuthUser> passwordHasher)
{
    var request = context.GetOpenIddictServerRequest()
        ?? throw new InvalidOperationException("The OpenIddict token request could not be retrieved.");

    AuthUser? user;
    if (request.IsPasswordGrantType())
    {
        var identifier = string.IsNullOrWhiteSpace(request.Username)
            ? request.GetParameter("email")?.ToString()?.Trim()
            : request.Username.Trim();

        var normalizedIdentifier = identifier?.ToUpperInvariant();
        user = string.IsNullOrWhiteSpace(normalizedIdentifier)
            ? null
            : await database.Users.SingleOrDefaultAsync(candidate =>
                candidate.NormalizedUsername == normalizedIdentifier ||
                candidate.NormalizedEmail == normalizedIdentifier);

        if (user is null ||
            passwordHasher.VerifyHashedPassword(
                user,
                user.PasswordHash,
                request.Password ?? string.Empty) == PasswordVerificationResult.Failed)
        {
            return InvalidGrant("The username/email or password is incorrect.");
        }
    }
    else if (request.IsAuthorizationCodeGrantType())
    {
        var authentication = await context.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        if (!authentication.Succeeded || authentication.Principal is null)
        {
            return InvalidGrant("The authorization code is invalid or has expired.");
        }

        return Results.SignIn(
            authentication.Principal,
            authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }
    else if (request.GrantType == AuthConstants.MagicLinkGrantType)
    {
        var rawToken = request.GetParameter("magic_token")?.ToString();
        if (string.IsNullOrWhiteSpace(rawToken))
        {
            return InvalidGrant("The magic link is invalid or has expired.");
        }

        var tokenHash = HashMagicLinkToken(rawToken);
        var magicLinkToken = await database.MagicLinkTokens.SingleOrDefaultAsync(
            token => token.TokenHash == tokenHash);
        var now = DateTimeOffset.UtcNow;
        if (magicLinkToken is null ||
            magicLinkToken.ConsumedAt is not null ||
            magicLinkToken.ExpiresAt <= now)
        {
            return InvalidGrant("The magic link is invalid or has expired.");
        }

        magicLinkToken.ConsumedAt = now;
        try
        {
            await database.SaveChangesAsync();
        }
        catch (DbUpdateConcurrencyException)
        {
            return InvalidGrant("The magic link is invalid or has expired.");
        }

        user = await database.Users.SingleOrDefaultAsync(
            candidate => candidate.Id == magicLinkToken.AuthUserId);
        if (user is null)
        {
            return InvalidGrant("The magic link is invalid or has expired.");
        }
    }
    else
    {
        return Results.BadRequest(new { error = OpenIddictConstants.Errors.UnsupportedGrantType });
    }

    return Results.SignIn(
        CreatePrincipal(user, request.GetScopes()),
        authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}

static ClaimsPrincipal CreatePrincipal(AuthUser user, IEnumerable<string> scopes)
{
    var identity = new ClaimsIdentity(
        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        OpenIddictConstants.Claims.Name,
        OpenIddictConstants.Claims.Role);
    identity.SetClaim(OpenIddictConstants.Claims.Subject, user.Id.ToString());
    identity.SetClaim(OpenIddictConstants.Claims.Name, user.Username);
    identity.SetClaim(OpenIddictConstants.Claims.Email, user.Email);

    var principal = new ClaimsPrincipal(identity);
    principal.SetScopes(scopes);
    principal.SetDestinations(claim => claim.Type switch
    {
        OpenIddictConstants.Claims.Subject => new[]
        {
            OpenIddictConstants.Destinations.AccessToken,
            OpenIddictConstants.Destinations.IdentityToken
        },
        OpenIddictConstants.Claims.Name => new[]
        {
            OpenIddictConstants.Destinations.AccessToken,
            OpenIddictConstants.Destinations.IdentityToken
        },
        OpenIddictConstants.Claims.Email => principal.GetScopes().Contains(OpenIddictConstants.Scopes.Email)
            ? new[]
            {
                OpenIddictConstants.Destinations.AccessToken,
                OpenIddictConstants.Destinations.IdentityToken
            }
            : Array.Empty<string>(),
        _ => Array.Empty<string>()
    });

    return principal;
}

static IResult InvalidGrant(string description)
{
    var properties = new AuthenticationProperties(new Dictionary<string, string?>
    {
        [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = description
    });
    return Results.Forbid(properties, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
}

static bool TryNormalizeEmail(string? input, out string email, out string normalizedEmail)
{
    email = input?.Trim() ?? string.Empty;
    normalizedEmail = string.Empty;
    if (email.Length is 0 or > 254 ||
        !System.Net.Mail.MailAddress.TryCreate(email, out var address) ||
        !string.Equals(address.Address, email, StringComparison.OrdinalIgnoreCase))
    {
        return false;
    }

    normalizedEmail = address.Address.ToUpperInvariant();
    return true;
}

static string HashMagicLinkToken(string token) =>
    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

static class AuthConstants
{
    public const string MagicLinkGrantType = "magic_link";
}
