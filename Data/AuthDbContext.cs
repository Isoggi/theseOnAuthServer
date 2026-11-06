using Microsoft.EntityFrameworkCore;
using theseOnAuthServer.Models;

namespace theseOnAuthServer.Data;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    public DbSet<AuthUser> Users => Set<AuthUser>();

    public DbSet<MagicLinkToken> MagicLinkTokens => Set<MagicLinkToken>();

    public DbSet<LoginChallenge> LoginChallenges => Set<LoginChallenge>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<AuthUser>()
            .HasIndex(user => user.NormalizedUsername)
            .IsUnique();

        builder.Entity<AuthUser>()
            .HasIndex(user => user.NormalizedEmail)
            .IsUnique();

        builder.Entity<MagicLinkToken>()
            .HasIndex(token => token.TokenHash)
            .IsUnique();

        builder.Entity<MagicLinkToken>()
            .Property(token => token.ConsumedAt)
            .IsConcurrencyToken();

        builder.Entity<LoginChallenge>()
            .HasIndex(challenge => challenge.ChallengeHash)
            .IsUnique();

        builder.Entity<LoginChallenge>()
            .Property(challenge => challenge.ConsumedAt)
            .IsConcurrencyToken();
    }
}
