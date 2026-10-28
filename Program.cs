using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using theseOnAuthServer.Data;
using theseOnAuthServer.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();
builder.Services.AddDbContext<AuthDbContext>(options =>
{
    options.UseInMemoryDatabase("auth");
    options.UseOpenIddict();
});
builder.Services.AddAuthorization();
builder.Services.AddSingleton<IPasswordHasher<AuthUser>, PasswordHasher<AuthUser>>();

X509Certificate2? productionCertificate = null;
if (!builder.Environment.IsDevelopment())
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
        options.SetTokenEndpointUris("/connect/token")
            .AllowPasswordFlow()
            .RegisterScopes(OpenIddictConstants.Scopes.OpenId, OpenIddictConstants.Scopes.Profile)
            .SetAccessTokenLifetime(TimeSpan.FromMinutes(15));

        options.UseAspNetCore()
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
    if (await applicationManager.FindByClientIdAsync("theseOnAuthServer") is null)
    {
        var application = new OpenIddictApplicationDescriptor
        {
            ClientId = "theseOnAuthServer",
            ClientType = OpenIddictConstants.ClientTypes.Public,
            DisplayName = "theseOnAuthServer first-party client"
        };
        application.Permissions.Add(OpenIddictConstants.Permissions.Endpoints.Token);
        application.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.Password);
        application.Permissions.Add(OpenIddictConstants.Permissions.Scopes.Profile);
        await applicationManager.CreateAsync(application);
    }
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/register", RegisterAsync).AllowAnonymous();
app.MapPost("/connect/token", LoginAsync).AllowAnonymous();

app.Run();

static async Task<IResult> RegisterAsync(
    RegisterRequest request,
    AuthDbContext database,
    IPasswordHasher<AuthUser> passwordHasher)
{
    var username = request.Username?.Trim();
    if (string.IsNullOrWhiteSpace(username) || username.Length is < 3 or > 64 ||
        username.Any(char.IsWhiteSpace))
    {
        return Results.BadRequest(new { error = "invalid_username", message = "Username must be 3-64 characters with no whitespace." });
    }

    if (string.IsNullOrWhiteSpace(request.Password) || request.Password.Length is < 12 or > 256)
    {
        return Results.BadRequest(new { error = "invalid_password", message = "Password must be 12-256 characters." });
    }

    var normalizedUsername = username.ToUpperInvariant();
    if (await database.Users.AnyAsync(user => user.NormalizedUsername == normalizedUsername))
    {
        return Results.Conflict(new { error = "username_taken" });
    }

    var user = new AuthUser
    {
        Id = Guid.NewGuid(),
        Username = username,
        NormalizedUsername = normalizedUsername
    };
    user.PasswordHash = passwordHasher.HashPassword(user, request.Password);

    database.Users.Add(user);
    await database.SaveChangesAsync();

    return Results.Json(new { user.Id, user.Username }, statusCode: StatusCodes.Status201Created);
}

static async Task<IResult> LoginAsync(
    HttpContext context,
    AuthDbContext database,
    IPasswordHasher<AuthUser> passwordHasher)
{
    var request = context.GetOpenIddictServerRequest()
        ?? throw new InvalidOperationException("The OpenIddict token request could not be retrieved.");

    if (!request.IsPasswordGrantType())
    {
        return Results.BadRequest(new { error = OpenIddictConstants.Errors.UnsupportedGrantType });
    }

    var normalizedUsername = request.Username?.Trim().ToUpperInvariant();
    var user = normalizedUsername is null
        ? null
        : await database.Users.SingleOrDefaultAsync(candidate =>
            candidate.NormalizedUsername == normalizedUsername);

    if (user is null ||
        passwordHasher.VerifyHashedPassword(user, user.PasswordHash, request.Password ?? string.Empty) ==
        PasswordVerificationResult.Failed)
    {
        var properties = new AuthenticationProperties(new Dictionary<string, string?>
        {
            [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
            [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "The username or password is incorrect."
        });
        return Results.Forbid(properties, new[] { OpenIddictServerAspNetCoreDefaults.AuthenticationScheme });
    }

    var identity = new ClaimsIdentity(
        OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
        OpenIddictConstants.Claims.Name,
        OpenIddictConstants.Claims.Role);
    identity.SetClaim(OpenIddictConstants.Claims.Subject, user.Id.ToString());
    identity.SetClaim(OpenIddictConstants.Claims.Name, user.Username);

    var principal = new ClaimsPrincipal(identity);
    principal.SetScopes(request.GetScopes());
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
        _ => Array.Empty<string>()
    });

    return Results.SignIn(
        principal,
        authenticationScheme: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
}
