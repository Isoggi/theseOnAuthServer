using Microsoft.EntityFrameworkCore;
using theseOnAuthServer.Models;

namespace theseOnAuthServer.Data;

public sealed class AuthDbContext(DbContextOptions<AuthDbContext> options) : DbContext(options)
{
    public DbSet<AuthUser> Users => Set<AuthUser>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<AuthUser>()
            .HasIndex(user => user.NormalizedUsername)
            .IsUnique();
    }
}
