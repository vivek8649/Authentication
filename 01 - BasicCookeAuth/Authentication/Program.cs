using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;

/**
 * Basic cookie auth - 
 * If user has cookie then do stuff
 * Drawback - 
 *  No surity that only my server issues it.
 *  No surity that only my server validates it.
 *  Microsoft created an API to handle this. - AddDataProtection 
 *
 
    var builder = WebApplication.CreateBuilder(args);
    var app = builder.Build();

    app.MapGet("/home", (HttpContext context) =>
    {
        var cookie = context.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
        var payload = cookie.Split("=").Last();
        var value = payload.Split(":");
        return value;

    });

    app.MapGet("/login", (HttpContext context) => {
        context.Response.Headers["set-cookie"] = "auth=user:vivek";
        return "ok";
    });
**/

/**
 * With DataProtectionProvider
 * Drawback -
 *  We don't want to put it on every endpoint so better put in a service and use it as a package
 *  We may not want to put it at everyother endpoint so we can do that in middleware

    var builder = WebApplication.CreateBuilder(args);
    builder.Services.AddDataProtection();
    var app = builder.Build();

    app.MapGet("/home", (HttpContext context, IDataProtectionProvider provider) =>
    {
        var protector = provider.CreateProtector("auth-cookie");

        var cookie = context.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
        var payload = cookie.Split("=").Last();
        var payloadDecoded = protector.Unprotect(payload);
        var value = payloadDecoded.Split(":");
        return value;

    });

    app.MapGet("/login", (HttpContext context, IDataProtectionProvider provider) => {
        context.Response.Headers["set-cookie"] = $"auth={provider.CreateProtector("auth-cookie").Protect("user:vivek")}";
        return "ok";
    });
**/

/**
 *  Using a seperate auth service like from .Net internal
 * 
    var builder = WebApplication.CreateBuilder(args);
    builder.Services.AddDataProtection();
    builder.Services.AddHttpContextAccessor();
    builder.Services.AddTransient<AuthService>();

    var app = builder.Build();

    app.Use((context, next) =>
    {
        var dpProvider = context.RequestServices.GetRequiredService<IDataProtectionProvider>();

        var protector = dpProvider.CreateProtector("auth-cookie");
        var cookie = context.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
        if (cookie != null)
        {
            var payload = cookie.Split("=").Last();
            var payloadDecoded = protector.Unprotect(payload);
            var value = payloadDecoded.Split(":");

            var claims = new List<Claim>();
            claims.Add(new Claim(value[0], value[1]));

            var identity = new ClaimsIdentity(claims);
            context.User = new System.Security.Claims.ClaimsPrincipal(identity);
        }
        return next();
    });

    app.MapGet("/home", (HttpContext context) =>
        {
            return context.User.FindFirst("user").Value;
        });

    app.MapGet("/login", (AuthService service) =>
    {
        service.SignIn();
        return "ok";
    });

    app.Run();

    public class AuthService
    {
        private readonly IDataProtectionProvider _provider;
        private readonly IHttpContextAccessor _httpContextAccessor;
        public AuthService(IDataProtectionProvider provider, IHttpContextAccessor httpContextAccessor)
        {
            _provider = provider;
            _httpContextAccessor = httpContextAccessor;
        }
        public void SignIn()
        {
            _httpContextAccessor.HttpContext.Response.Headers["set-cookie"] = $"auth={_provider.CreateProtector("auth-cookie").Protect("user:vivek")}";
        }
    }
**/


/* Using builtin Authetication
 */

var builder = WebApplication.CreateBuilder(args);

// Cookie Authentication is responsible for loading the cookie and then writing back, validating, splitting
builder.Services.AddAuthentication("cookie")
    .AddCookie("cookie");

var app = builder.Build();

app.UseAuthentication(); // Middleware to do what we did in app.use, i.e add user on context if available from the right authentication method

// HttpContext - When we make a http request everything from the url to headers is shoved into httpcontext till the end of response reaching to client.
//              Lifetime of handling of that request is in context.
app.MapGet("/home", (HttpContext context) =>
{
    return context.User.FindFirst("user").Value;
});

app.MapGet("/login", async (HttpContext ctx) =>
{
    // Claims – User identification, like government give passport and has an ID
    var claims = new List<Claim>();
    claims.Add(new Claim("user", "vivek"));

    var identity = new ClaimsIdentity(claims, "cookie");
    var claimsPrincipal = new ClaimsPrincipal(identity);

    await ctx.SignInAsync("cookie", claimsPrincipal);
    return "ok";
});

app.Run();
