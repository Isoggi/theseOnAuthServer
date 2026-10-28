namespace theseOnAuthServer.Models;

public sealed class AuthUser
{
    public Guid Id { get; set; }

    public required string Username { get; set; }

    public required string NormalizedUsername { get; set; }

    public string PasswordHash { get; set; } = string.Empty;
}

public sealed record RegisterRequest(string? Username, string? Password);
