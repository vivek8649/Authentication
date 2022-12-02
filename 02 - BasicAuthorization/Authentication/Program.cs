using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

const string AUTH_SCHEME = "cookie";
const string SWN_POLICY = "swn passport";


var builder = WebApplication.CreateBuilder(args);

// Cookie Authentication is responsible for loading the cookie and then writing back, validating, splitting
builder.Services.AddAuthentication(AUTH_SCHEME)
    .AddCookie(AUTH_SCHEME);
builder.Services.AddSingleton<IAuthorizationHandler, MyRequirementHandler>();


builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy(SWN_POLICY, pb =>
    {
        pb.RequireAuthenticatedUser()
            .AddAuthenticationSchemes(AUTH_SCHEME)
            .AddRequirements(new MinimumAgeRequirement(21))
            .RequireClaim("passport", "swn");
    });
});

var app = builder.Build();

// Middleware to do what we did in app.use, i.e add user on context if available from the right authentication method
app.UseAuthentication(); 
app.UseAuthorization();

/*****
 *  This is a rough implementation without using policy
 * 
app.Use((ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/login")) {
        return next();
    }


    if (!ctx.User.Identities.Any(x => x.AuthenticationType.Equals(AUTH_SCHEME)))
    {
        ctx.Response.StatusCode = 401;
        return Task.CompletedTask;
    }

    if (!ctx.User.HasClaim("passport", "swn"))
    {
        ctx.Response.StatusCode = 403;
        return Task.CompletedTask;
    }
    return next();
});
******************************/

// HttpContext - When we make a http request everything from the url to headers is shoved into httpcontext till the end of response reaching to client.
//              Lifetime of handling of that request is in context.

// Authorize[Policy="swn passport"]
app.MapGet("/home", (HttpContext context) =>
{
    return context?.User?.FindFirst("user")?.Value;
}).RequireAuthorization(SWN_POLICY);


app.MapGet("/login", async (HttpContext ctx) =>
{
    // Claims – User identification, like government give passport and has an ID
    var claims = new List<Claim>();
    claims.Add(new Claim("user", "vivek"));

    claims.Add(new Claim("passport", "swn"));

    var date = DateTime.Now;
    var age = date.AddYears(-20);
    claims.Add(new Claim(ClaimTypes.DateOfBirth, age.ToString(), ClaimValueTypes.DateTime, "http://contoso.com"));


    var identity = new ClaimsIdentity(claims, AUTH_SCHEME);
    var claimsPrincipal = new ClaimsPrincipal(identity);

    await ctx.SignInAsync(AUTH_SCHEME, claimsPrincipal);
    return "ok";
}).AllowAnonymous();

app.Run();

//For handling the requriment
// https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies?view=aspnetcore-7.0
public class MinimumAgeRequirement : IAuthorizationRequirement {
    public MinimumAgeRequirement(int minimumAge) =>
            MinimumAge = minimumAge;

    public int MinimumAge { get; }
}

public class MyRequirementHandler : AuthorizationHandler<MinimumAgeRequirement>
{
    // You can inject the service like DB connection or cache and do anything here at authorization level
    public MyRequirementHandler() { }
    protected override Task HandleRequirementAsync(
         AuthorizationHandlerContext context, MinimumAgeRequirement requirement)
    {
        var dateOfBirthClaim = context.User.FindFirst(
            c => c.Type == ClaimTypes.DateOfBirth && c.Issuer == "http://contoso.com");

        if (dateOfBirthClaim is null)
        {
            return Task.CompletedTask;
        }

        var dateOfBirth = Convert.ToDateTime(dateOfBirthClaim.Value);
        int calculatedAge = DateTime.Today.Year - dateOfBirth.Year;
        if (dateOfBirth > DateTime.Today.AddYears(-calculatedAge))
        {
            calculatedAge--;
        }

        if (calculatedAge >= requirement.MinimumAge)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
