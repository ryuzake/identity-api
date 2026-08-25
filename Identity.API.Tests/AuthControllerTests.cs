using Identity.API.Controllers;
using Identity.API.Data;
using Identity.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Identity.API.Tests;

public class AuthControllerTests
{
    private AppDbContext CreateInMemoryDb()
    {
        var options = new DbContextOptionsBuilder<AppDbContext>()
            .UseInMemoryDatabase(Guid.NewGuid().ToString())
            .Options;
        return new AppDbContext(options);
    }

    private IConfiguration CreateConfig()
    {
        return new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Key"] = "SuperSecretTestKeyThatIsLongEnough1234567890",
                ["Jwt:Issuer"] = "test-issuer",
                ["Jwt:Audience"] = "test-audience",
                ["Jwt:ExpiryMinutes"] = "60"
            })
            .Build();
    }

    [Fact]
    public async Task Register_ValidRequest_ReturnsCreatedWithToken()
    {
        var db = CreateInMemoryDb();
        var controller = new AuthController(db, CreateConfig());

        var result = await controller.Register(new RegisterRequest
        {
            Username = "testuser",
            Email = "test@example.com",
            Password = "P@ssw0rd"
        });

        var created = Assert.IsType<CreatedResult>(result);
        var response = Assert.IsType<AuthResponse>(created.Value);
        Assert.NotEmpty(response.Token);
        Assert.Equal("testuser", response.Username);
        Assert.Equal(1, await db.Users.CountAsync());
    }

    [Fact]
    public async Task Register_MissingUsername_ReturnsBadRequest()
    {
        var db = CreateInMemoryDb();
        var controller = new AuthController(db, CreateConfig());

        var result = await controller.Register(new RegisterRequest
        {
            Username = "",
            Email = "test@example.com",
            Password = "P@ssw0rd"
        });

        Assert.IsType<BadRequestObjectResult>(result);
    }

    [Fact]
    public async Task Register_DuplicateUsername_ReturnsConflict()
    {
        var db = CreateInMemoryDb();
        db.Users.Add(new User
        {
            Username = "testuser",
            Email = "existing@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("pass"),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        var controller = new AuthController(db, CreateConfig());

        var result = await controller.Register(new RegisterRequest
        {
            Username = "testuser",
            Email = "new@example.com",
            Password = "P@ssw0rd"
        });

        Assert.IsType<ConflictObjectResult>(result);
    }

    [Fact]
    public async Task Login_ValidCredentials_ReturnsToken()
    {
        var db = CreateInMemoryDb();
        db.Users.Add(new User
        {
            Username = "testuser",
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("P@ssw0rd"),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        var controller = new AuthController(db, CreateConfig());

        var result = await controller.Login(new LoginRequest
        {
            Username = "testuser",
            Password = "P@ssw0rd"
        });

        var ok = Assert.IsType<OkObjectResult>(result);
        var response = Assert.IsType<AuthResponse>(ok.Value);
        Assert.NotEmpty(response.Token);
        Assert.Equal("testuser", response.Username);
    }

    [Fact]
    public async Task Login_WrongPassword_ReturnsUnauthorized()
    {
        var db = CreateInMemoryDb();
        db.Users.Add(new User
        {
            Username = "testuser",
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("P@ssw0rd"),
            CreatedAt = DateTime.UtcNow,
            UpdatedAt = DateTime.UtcNow
        });
        await db.SaveChangesAsync();

        var controller = new AuthController(db, CreateConfig());

        var result = await controller.Login(new LoginRequest
        {
            Username = "testuser",
            Password = "WrongPassword"
        });

        Assert.IsType<UnauthorizedObjectResult>(result);
    }

    [Fact]
    public async Task Login_NonexistentUser_ReturnsUnauthorized()
    {
        var db = CreateInMemoryDb();
        var controller = new AuthController(db, CreateConfig());

        var result = await controller.Login(new LoginRequest
        {
            Username = "nobody",
            Password = "P@ssw0rd"
        });

        Assert.IsType<UnauthorizedObjectResult>(result);
    }
}
