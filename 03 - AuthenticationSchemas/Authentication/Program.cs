using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;

/**
 * Authentication Schemas - 
 */
const string LOCAL_AUTH_SCHEME = "local";
const string VISITOR_AUTH_SCHEME = "visitor";
const string PATREON_AUTH_SCHEME = "patreon";

const string CUSTOMER_POLICY = "customer";
const string USER_POLICY = "user";


var builder = WebApplication.CreateBuilder(args);

// Cookie Authentication is responsible for loading the cookie and then writing back, validating, splitting
builder.Services.AddAuthentication()
    .AddScheme<CookieAuthenticationOptions, VisitorHandler>(VISITOR_AUTH_SCHEME, o => {})
    .AddCookie(LOCAL_AUTH_SCHEME)
    .AddCookie(PATREON_AUTH_SCHEME)
    .AddOAuth("external-patreon", o =>
    {
        o.SignInScheme= PATREON_AUTH_SCHEME;

        o.ClientId = "id";
        o.ClientSecret = "secret";
        o.AuthorizationEndpoint = "https://oauth.mocklab.io/oauth/authorize";
        o.TokenEndpoint = "https://oauth.mocklab.io/oauth/token";
        o.UserInformationEndpoint = "https://oauth.mocklab.io/userinfo";

        o.CallbackPath= "/cb-patreon";
        o.SaveTokens = true;
    });

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy(CUSTOMER_POLICY, pb =>
    {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(VISITOR_AUTH_SCHEME, LOCAL_AUTH_SCHEME, PATREON_AUTH_SCHEME);
    });

    builder.AddPolicy(USER_POLICY, pb =>
    {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(LOCAL_AUTH_SCHEME);
    });
});

var app = builder.Build();

// Middleware to do what we did in app.use, i.e add user on context if available from the right authentication method
app.UseAuthentication(); 
app.UseAuthorization();


app.MapGet("/", (HttpContext context) =>
{
    return Task.FromResult("hello world!");
}).RequireAuthorization(CUSTOMER_POLICY);

app.MapGet("/home", (HttpContext context) =>
{
    return context?.User?.FindFirst("user")?.Value;
});


app.MapGet("/login-local", async (HttpContext ctx) =>
{
    // Claims – User identification, like government give passport and has an ID
    var claims = new List<Claim>();
    claims.Add(new Claim("user", "vivek"));

    var identity = new ClaimsIdentity(claims, LOCAL_AUTH_SCHEME);
    var claimsPrincipal = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(LOCAL_AUTH_SCHEME, claimsPrincipal);
    return "ok";
});

app.MapGet("/login-patreon", async (ctx) =>
{
    // Claims – User identification, like government give passport and has an ID
    await ctx.ChallengeAsync("external-patreon", new AuthenticationProperties()
    {
        RedirectUri = "/"
    });
}).RequireAuthorization(USER_POLICY);

app.Run();

public class VisitorHandler : CookieAuthenticationHandler
{
    const string VISITOR_AUTH_SCHEME = "visitor";

    public VisitorHandler(IOptionsMonitor<CookieAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
    {
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var result = await base.HandleAuthenticateAsync();
        
        if (result.Succeeded)
        {
            return result;
        }

        var claims = new List<Claim>();
        claims.Add(new Claim("user", "vivek"));

        var identity = new ClaimsIdentity(claims, VISITOR_AUTH_SCHEME);
        var claimsPrincipal = new ClaimsPrincipal(identity);

        await Context.SignInAsync(VISITOR_AUTH_SCHEME, claimsPrincipal);
        return AuthenticateResult.Success(new AuthenticationTicket(claimsPrincipal, VISITOR_AUTH_SCHEME));

    }
}