namespace theseOnAuthServer.Models;

public sealed class AuthUser
{
    public Guid Id { get; set; }

    public required string Username { get; set; }

    public required string NormalizedUsername { get; set; }

    public required string Email { get; set; }

    public required string NormalizedEmail { get; set; }

    public string PasswordHash { get; set; } = string.Empty;
}

public sealed class MagicLinkToken
{
    public Guid Id { get; set; }

    public Guid AuthUserId { get; set; }

    public required string TokenHash { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }
}

public sealed class LoginChallenge
{
    public Guid Id { get; set; }

    public required string ChallengeHash { get; set; }

    public required string ReturnUrl { get; set; }

    public DateTimeOffset ExpiresAt { get; set; }

    public DateTimeOffset? ConsumedAt { get; set; }
}

public sealed record RegisterRequest(string? Username, string? Email, string? Password);

public sealed record MagicLinkRequest(string? Email);
